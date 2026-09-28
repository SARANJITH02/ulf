package com.ulpf.normalization;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ulpf.detection.FormatClassificationResult;
import com.ulpf.detection.FormatClassifier;
import com.ulpf.domain.NormalizedEvent;
import com.ulpf.domain.RawEvent;
import com.ulpf.enrichment.IanaPortService;
import com.ulpf.enrichment.MitreMapper;
import com.ulpf.enrichment.OfflineIpClassifier;
import com.ulpf.lineage.CryptographicLineageService;
import com.ulpf.metrics.LivePipelineMetrics;
import com.ulpf.parsers.DynamicParserRegistry;
import com.ulpf.parsers.ParsedLogResult;
import com.ulpf.parsers.ParserPlugin;
import com.ulpf.repository.NormalizedEventRepository;
import com.ulpf.repository.RawEventRepository;
import com.ulpf.rules.RuleEngine;
import com.ulpf.rules.SigmaRuleService;
import com.ulpf.validation.DlqService;
import com.ulpf.validation.EventValidator;
import com.ulpf.validation.ValidationResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class NormalizationEngine {

    private final CryptographicLineageService lineageService;
    private final RawEventRepository rawEventRepository;
    private final NormalizedEventRepository normalizedEventRepository;
    private final FormatClassifier formatClassifier;
    private final DynamicParserRegistry parserRegistry;
    private final OfflineIpClassifier ipClassifier;
    private final IanaPortService ianaPortService;
    private final MitreMapper mitreMapper;
    private final SigmaRuleService sigmaRuleService;
    private final EventValidator eventValidator;
    private final DlqService dlqService;
    private final RuleEngine ruleEngine;
    private final ConfidenceScorer confidenceScorer;
    private final EcsAliasMap ecsAliasMap;
    private final LivePipelineMetrics liveMetrics;
    private final com.ulpf.metrics.MetricsBroadcaster metricsBroadcaster;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Process raw incoming log string end-to-end through the complete pipeline.
     */
    @Transactional
    public ProcessedLogOutput processLog(String rawMessage, String ingestionSource) {
        long startTimeNanos = System.nanoTime();
        if (rawMessage == null) rawMessage = "";

        // 1. Cryptographic Lineage Layer: compute SHA-256 before any parsing
        String rawHash = lineageService.computeSha256(rawMessage);
        String rawEventId = lineageService.generateRawEventId(rawHash);

        // 2. Format Classification
        FormatClassificationResult classification = formatClassifier.classify(rawMessage);

        // 3. Persist Raw Event
        RawEvent rawEvent = RawEvent.builder()
                .rawEventId(rawEventId)
                .rawHashSha256(rawHash)
                .rawMessage(rawMessage)
                .ingestionSource(ingestionSource != null ? ingestionSource : "REST")
                .receivedAt(Instant.now())
                .detectedFormat(classification.getFormat().name())
                .processingStatus("PROCESSING")
                .build();
        rawEventRepository.save(rawEvent);

        // 4. Locate matching parser plugin
        Optional<ParserPlugin> parserOpt = parserRegistry.findMatchingParser(rawMessage, classification.getFormat());

        if (parserOpt.isEmpty()) {
            rawEvent.setProcessingStatus("DLQ");
            rawEventRepository.save(rawEvent);
            dlqService.sendToDlq(rawEventId, rawMessage, "UNPARSEABLE_FORMAT",
                    "No active parser matched format: " + classification.getFormat() + " (" + classification.getDetails() + ")",
                    classification.getFormat().name());
            liveMetrics.recordEvent(classification.getFormat().name(), 0.0, false, (System.nanoTime() - startTimeNanos) / 1_000_000.0);
            return ProcessedLogOutput.builder()
                    .success(false)
                    .rawEventId(rawEventId)
                    .rawHashSha256(rawHash)
                    .errorMessage("No active parser could process this format")
                    .build();
        }

        ParserPlugin parser = parserOpt.get();
        ParsedLogResult parseResult = parser.parse(rawMessage);

        if (!parseResult.isSuccess() || parseResult.getNormalizedEvent() == null) {
            rawEvent.setProcessingStatus("DLQ");
            rawEventRepository.save(rawEvent);
            dlqService.sendToDlq(rawEventId, rawMessage, "PARSER_FAILURE",
                    parseResult.getErrorMessage() != null ? parseResult.getErrorMessage() : "Parser failed on payload",
                    parser.getFormatType());
            liveMetrics.recordEvent(parser.getFormatType(), 0.0, false, (System.nanoTime() - startTimeNanos) / 1_000_000.0);
            return ProcessedLogOutput.builder()
                    .success(false)
                    .rawEventId(rawEventId)
                    .rawHashSha256(rawHash)
                    .errorMessage(parseResult.getErrorMessage())
                    .build();
        }

        OcsfSchema ocsf = parseResult.getNormalizedEvent();

        // 5. Lineage & Identity Injection
        String eventId = lineageService.generateNormalizedEventId();
        ocsf.setEventId(eventId);
        ocsf.setRawEventId(rawEventId);
        ocsf.setRawHashSha256(rawHash);
        if (ocsf.getTimestampUtc() == null) {
            ocsf.setTimestampUtc(Instant.now().toString());
        }

        // 6. Offline Enrichment
        boolean rfc1918Enabled = ruleEngine.getBooleanRule(RuleEngine.KEY_ENRICH_RFC1918, true);
        if (rfc1918Enabled) {
            if (ocsf.getSource() != null && ocsf.getSource().getIp() != null) {
                ocsf.getSource().setIsInternal(ipClassifier.isInternal(ocsf.getSource().getIp()));
            }
            if (ocsf.getDestination() != null && ocsf.getDestination().getIp() != null) {
                ocsf.getDestination().setIsInternal(ipClassifier.isInternal(ocsf.getDestination().getIp()));
            }
        }

        // Port enrichment
        if (ocsf.getDestination() != null && ocsf.getDestination().getPort() != null) {
            String service = ianaPortService.resolveService(ocsf.getDestination().getPort());
            if (service != null && (ocsf.getNetwork().getTransport() == null)) {
                ocsf.getNetwork().setTransport(service);
            }
        }

        // Heuristic MITRE ATT&CK Tagging
        boolean mitreEnabled = ruleEngine.getBooleanRule(RuleEngine.KEY_ENRICH_MITRE, true);
        if (mitreEnabled && (ocsf.getThreat() == null || ocsf.getThreat().getMitreTechniqueId() == null)) {
            OcsfSchema.ThreatDetail threat = mitreMapper.evaluateThreat(ocsf);
            if (threat != null) {
                ocsf.setThreat(threat);
            }
        }

        // Embedded Sigma Detection Rule Engine Evaluation
        boolean sigmaEnabled = ruleEngine.getBooleanRule("rules.sigma.enabled", true);
        List<OcsfSchema.SigmaMatchSummary> sigmaMatches = null;
        if (sigmaEnabled) {
            sigmaMatches = sigmaRuleService.evaluate(ocsf);
            if (sigmaMatches != null && !sigmaMatches.isEmpty()) {
                if (ocsf.getThreat() == null) {
                    ocsf.setThreat(new OcsfSchema.ThreatDetail());
                }
                ocsf.getThreat().setSigmaMatches(sigmaMatches);
            }
        }

        // 7. ECS Alias Map & Confidence
        if (ocsf.getUlpf() == null) {
            ocsf.setUlpf(new OcsfSchema.UlpfMetadata());
        }
        ocsf.getUlpf().setParserName(parser.getName());
        ocsf.getUlpf().setParserVersion(parser.getVersion());
        ocsf.getUlpf().setEcsAliases(ecsAliasMap.getAliases());

        double avgConfidence = confidenceScorer.calculateAverageConfidence(parseResult.getFieldConfidence());
        ocsf.getUlpf().setMappingConfidence(parseResult.getFieldConfidence());
        ocsf.getUlpf().setAverageConfidence(avgConfidence);

        // Check against confidence threshold
        double minHighThreshold = ruleEngine.getDoubleRule(RuleEngine.KEY_CONFIDENCE_HIGH, 0.90);
        double minMedThreshold = ruleEngine.getDoubleRule(RuleEngine.KEY_CONFIDENCE_MED, 0.70);

        if (avgConfidence < minMedThreshold) {
            log.warn("Event {} has low average confidence ({} < {}), marking for inspection", eventId, avgConfidence, minMedThreshold);
            ocsf.getUlpf().setDlqStatus("LOW_CONFIDENCE");
        }

        // 8. Event Validation
        ValidationResult valResult = eventValidator.validate(ocsf);
        if (!valResult.isValid()) {
            rawEvent.setProcessingStatus("DLQ");
            rawEventRepository.save(rawEvent);
            dlqService.sendToDlq(rawEventId, rawMessage, valResult.getFailureCode(), valResult.getFailureReason(), parser.getFormatType());
            liveMetrics.recordEvent(parser.getFormatType(), avgConfidence, false, (System.nanoTime() - startTimeNanos) / 1_000_000.0);
            return ProcessedLogOutput.builder()
                    .success(false)
                    .rawEventId(rawEventId)
                    .rawHashSha256(rawHash)
                    .errorMessage(valResult.getFailureReason())
                    .build();
        }

        // 9. Persist Normalized Event
        String ocsfJsonStr;
        try {
            ocsfJsonStr = objectMapper.writeValueAsString(ocsf);
        } catch (Exception e) {
            ocsfJsonStr = "{}";
        }

        Instant eventTime = Instant.now();
        try {
            eventTime = Instant.parse(ocsf.getTimestampUtc());
        } catch (Exception ignored) {}

        NormalizedEvent normEntity = NormalizedEvent.builder()
                .eventId(eventId)
                .rawEventId(rawEventId)
                .rawHashSha256(rawHash)
                .timestampUtc(eventTime)
                .category(ocsf.getEvent() != null ? ocsf.getEvent().getCategory() : "network_traffic")
                .eventType(ocsf.getEvent() != null ? ocsf.getEvent().getType() : "firewall")
                .action(ocsf.getEvent() != null ? ocsf.getEvent().getAction() : "allowed")
                .severity(ocsf.getEvent() != null ? ocsf.getEvent().getSeverity() : "informational")
                .sourceIp(ocsf.getSource() != null ? ocsf.getSource().getIp() : null)
                .sourcePort(ocsf.getSource() != null ? ocsf.getSource().getPort() : null)
                .destinationIp(ocsf.getDestination() != null ? ocsf.getDestination().getIp() : null)
                .destinationPort(ocsf.getDestination() != null ? ocsf.getDestination().getPort() : null)
                .protocol(ocsf.getNetwork() != null ? ocsf.getNetwork().getProtocol() : null)
                .observerVendor(ocsf.getObserver() != null ? ocsf.getObserver().getVendor() : null)
                .observerProduct(ocsf.getObserver() != null ? ocsf.getObserver().getProduct() : null)
                .parserName(parser.getName())
                .parserVersion(parser.getVersion())
                .averageConfidence(avgConfidence)
                .format(parser.getFormatType())
                .ocsfJson(ocsfJsonStr)
                .processedAt(Instant.now())
                .build();

        normalizedEventRepository.save(normEntity);

        rawEvent.setProcessingStatus("PROCESSED");
        rawEventRepository.save(rawEvent);

        // Record Sigma matches and broadcast to /topic/alerts
        if (sigmaMatches != null && !sigmaMatches.isEmpty()) {
            sigmaRuleService.recordMatches(ocsf, sigmaMatches);
        }

        // Broadcast to live WebSocket event tail
        metricsBroadcaster.broadcastEvent(ocsf);

        double latencyMs = (System.nanoTime() - startTimeNanos) / 1_000_000.0;
        liveMetrics.recordEvent(parser.getFormatType(), avgConfidence, true, latencyMs);

        return ProcessedLogOutput.builder()
                .success(true)
                .eventId(eventId)
                .rawEventId(rawEventId)
                .rawHashSha256(rawHash)
                .normalizedEvent(ocsf)
                .format(parser.getFormatType())
                .parserName(parser.getName())
                .averageConfidence(avgConfidence)
                .processingLatencyMs(latencyMs)
                .build();
    }
}
