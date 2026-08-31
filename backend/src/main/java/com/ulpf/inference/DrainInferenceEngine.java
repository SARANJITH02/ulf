package com.ulpf.inference;

import com.ulpf.domain.FieldMapping;
import com.ulpf.normalization.ConfidenceScorer;
import com.ulpf.normalization.OcsfSchema;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class DrainInferenceEngine implements ParserInferenceEngine {

    private final DrainStyleTemplateMiner templateMiner;
    private final SemanticFieldRecognizer fieldRecognizer;
    private final ConfidenceScorer confidenceScorer;

    @Override
    public String getStrategyName() {
        return "DrainStyleInference";
    }

    @Override
    public InferenceResult infer(String rawLog) {
        if (rawLog == null || rawLog.isBlank()) {
            return InferenceResult.builder()
                    .rawSample(rawLog)
                    .overallConfidence(0.0)
                    .confidenceTier("LOW")
                    .recommendedForApproval(false)
                    .build();
        }

        // --- STAGE 1: STRUCTURAL TEMPLATE MINING ---
        DrainStyleTemplateMiner.TemplateMiningResult mining = templateMiner.mine(rawLog);

        // --- STAGE 2: SEMANTIC FIELD RECOGNITION ---
        List<FieldMapping> mappings = new ArrayList<>();
        Map<String, Double> confidenceMatrix = new HashMap<>();

        Map<String, Object> extractedForPreview = new HashMap<>();
        Map<String, Object> extensions = new HashMap<>();

        String srcIp = null;
        Integer srcPort = null;
        String dstIp = null;
        Integer dstPort = null;
        String protocol = "TCP";
        String action = "allowed";
        String severity = "informational";
        int severityId = 1;
        String vendorCode = null;
        String timestamp = Instant.now().toString();

        List<String> rawTokens = mining.getRawTokens();
        for (int i = 0; i < rawTokens.size(); i++) {
            String token = rawTokens.get(i);
            String prevToken = i > 0 ? rawTokens.get(i - 1) : "";
            SemanticFieldRecognizer.RecognizedSemanticType recognized = fieldRecognizer.recognize(token, prevToken, i);

            String slotName = "token" + i;
            String canonical = recognized.getSuggestedOcsfPath();
            double conf = recognized.getConfidence();

            mappings.add(FieldMapping.builder()
                    .slotName(slotName)
                    .canonicalPath(canonical)
                    .inferredType(recognized.getSemanticType())
                    .confidence(conf)
                    .sampleValue(token)
                    .userOverridden(false)
                    .build());

            confidenceMatrix.put(canonical, conf);
            extractedForPreview.put(slotName, token);

            // Populate preview fields
            if (canonical.equals("source.ip")) {
                srcIp = recognized.getExtractedValue();
                if (recognized.getAuxiliaryValue() != null) {
                    try { srcPort = Integer.parseInt(recognized.getAuxiliaryValue()); } catch (Exception ignored) {}
                }
            } else if (canonical.equals("destination.ip")) {
                dstIp = recognized.getExtractedValue();
                if (recognized.getAuxiliaryValue() != null) {
                    try { dstPort = Integer.parseInt(recognized.getAuxiliaryValue()); } catch (Exception ignored) {}
                }
            } else if (canonical.equals("source.port")) {
                try { srcPort = Integer.parseInt(recognized.getExtractedValue()); } catch (Exception ignored) {}
            } else if (canonical.equals("destination.port")) {
                try { dstPort = Integer.parseInt(recognized.getExtractedValue()); } catch (Exception ignored) {}
            } else if (canonical.equals("network.protocol")) {
                protocol = recognized.getExtractedValue();
            } else if (canonical.equals("event.action")) {
                action = recognized.getExtractedValue();
                if (action.equalsIgnoreCase("blocked") || action.equalsIgnoreCase("denied") || action.equalsIgnoreCase("drop")) {
                    severity = "high";
                    severityId = 4;
                }
            } else if (canonical.equals("timestampUtc")) {
                timestamp = recognized.getExtractedValue();
            } else if (canonical.equals("extensions.vendorCode")) {
                vendorCode = recognized.getExtractedValue();
                extensions.put("vendorCode", vendorCode);
            } else {
                extensions.put(slotName, token);
            }
        }

        double avgConfidence = confidenceScorer.calculateAverageConfidence(confidenceMatrix);
        String tier = confidenceScorer.getConfidenceTier(avgConfidence);
        boolean recommendApproval = avgConfidence >= 0.85;

        // Build preview OCSF event
        OcsfSchema preview = OcsfSchema.builder()
                .eventId("PREVIEW-0000-0000-0000")
                .timestampUtc(timestamp)
                .event(OcsfSchema.EventDetail.builder()
                        .category("network_traffic")
                        .type("custom_inferred")
                        .action(action)
                        .severity(severity)
                        .severityId(severityId)
                        .message("Inferred log event from template: " + mining.getTemplate())
                        .build())
                .source(OcsfSchema.Endpoint.builder()
                        .ip(srcIp)
                        .port(srcPort)
                        .build())
                .destination(OcsfSchema.Endpoint.builder()
                        .ip(dstIp)
                        .port(dstPort)
                        .build())
                .network(OcsfSchema.NetworkDetail.builder()
                        .protocol(protocol)
                        .direction("egress")
                        .build())
                .observer(OcsfSchema.ObserverDetail.builder()
                        .vendor("CustomInferred")
                        .product("DynamicGateway")
                        .build())
                .raw(OcsfSchema.RawDetail.builder()
                        .message(rawLog)
                        .format("CUSTOM_INFERRED")
                        .build())
                .extensions(extensions)
                .ulpf(OcsfSchema.UlpfMetadata.builder()
                        .parserName("custom_inferred_parser")
                        .parserVersion("1.0-draft")
                        .mappingConfidence(confidenceMatrix)
                        .averageConfidence(avgConfidence)
                        .build())
                .build();

        return InferenceResult.builder()
                .rawSample(rawLog)
                .minedTemplate(mining.getTemplate())
                .synthesizedRegex(mining.getRegexPattern())
                .suggestedParserName("custom_" + Math.abs(rawLog.hashCode() % 10000) + "_parser")
                .suggestedFormat("CUSTOM")
                .inferredMappings(mappings)
                .confidenceMatrix(confidenceMatrix)
                .overallConfidence(avgConfidence)
                .confidenceTier(tier)
                .recommendedForApproval(recommendApproval)
                .previewNormalizedEvent(preview)
                .stage1Miner("DrainStyleTemplateMiner")
                .stage2Recognizer("DeterministicSemanticFieldRecognizer")
                .build();
    }
}
