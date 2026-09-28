package com.ulpf.parsers.monitoring;

import com.ulpf.domain.DriftAlert;
import com.ulpf.domain.NormalizedEvent;
import com.ulpf.domain.ParserEntity;
import com.ulpf.domain.ParserVersion;
import com.ulpf.metrics.MetricsBroadcaster;
import com.ulpf.parsers.DynamicGeneratedParser;
import com.ulpf.parsers.DynamicParserRegistry;
import com.ulpf.parsers.ParserPlugin;
import com.ulpf.repository.DlqEntryRepository;
import com.ulpf.repository.DriftAlertRepository;
import com.ulpf.repository.NormalizedEventRepository;
import com.ulpf.repository.ParserEntityRepository;
import com.ulpf.repository.ParserVersionRepository;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class ParserDriftMonitorService {

    private final DynamicParserRegistry parserRegistry;
    private final NormalizedEventRepository normalizedEventRepository;
    private final DlqEntryRepository dlqEntryRepository;
    private final DriftAlertRepository driftAlertRepository;
    private final ParserEntityRepository parserEntityRepository;
    private final ParserVersionRepository parserVersionRepository;
    private final MetricsBroadcaster metricsBroadcaster;

    @Value("${ulpf.drift.confidence-drop-threshold:0.15}")
    private double confidenceDropThreshold;

    @Value("${ulpf.drift.success-rate-threshold:0.85}")
    private double successRateThreshold;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ParserDriftMetricsDto {
        private String parserName;
        private String parserVersion;
        private String formatType;
        private double baselineConfidence;
        private double currentConfidence;
        private double confidenceDrop;
        private double successRate;
        private int sampleCount;
        private long dlqCount;
        private String healthStatus; // HEALTHY, WARNING, DRIFT_ALERT
        private boolean activeAlert;
        private List<Double> confidenceHistory;
        private Instant lastChecked;
    }

    /**
     * Periodic background task to assess parser quality drift.
     */
    @Scheduled(fixedRateString = "${ulpf.drift.check-interval-ms:300000}")
    @Transactional
    public List<DriftAlert> checkDrift() {
        log.info("Running Parser Drift Detection scan across active parsers...");
        List<DriftAlert> newAlerts = new ArrayList<>();

        for (ParserPlugin parser : parserRegistry.getActiveParsers()) {
            if (!parser.isActive()) continue;

            try {
                Optional<DriftAlert> alertOpt = evaluateParserDrift(parser);
                alertOpt.ifPresent(newAlerts::add);
            } catch (Exception e) {
                log.error("Error checking drift for parser {}: {}", parser.getName(), e.getMessage());
            }
        }

        return newAlerts;
    }

    /**
     * Trigger drift check on demand.
     */
    @Transactional
    public List<DriftAlert> checkDriftNow() {
        return checkDrift();
    }

    @Transactional
    public Optional<DriftAlert> evaluateParserDrift(ParserPlugin parser) {
        String parserName = parser.getName();
        List<NormalizedEvent> recentEvents = normalizedEventRepository.findTop500ByParserNameOrderByProcessedAtDesc(parserName);

        if (recentEvents.isEmpty()) {
            return Optional.empty();
        }

        // Determine baseline confidence
        double baseline = getParserBaselineConfidence(parser);

        // Compute rolling confidence
        double currentConfidence = recentEvents.stream()
                .mapToDouble(e -> e.getAverageConfidence() != null ? e.getAverageConfidence() : 0.8)
                .average()
                .orElse(baseline);

        // Compute success rate vs DLQ entries over last 24h
        Instant cutoff = Instant.now().minus(Duration.ofHours(24));
        long dlqCount = dlqEntryRepository.countByDetectedFormatAndCreatedAtAfter(parser.getFormatType(), cutoff);
        long successCount = recentEvents.size();
        double successRate = (successCount + dlqCount > 0)
                ? (double) successCount / (successCount + dlqCount)
                : 1.0;

        double confidenceDrop = Math.max(0.0, baseline - currentConfidence);

        boolean confidenceBreach = confidenceDrop >= confidenceDropThreshold;
        boolean successRateBreach = successRate < successRateThreshold && (successCount + dlqCount) >= 5;

        if (confidenceBreach || successRateBreach) {
            Optional<DriftAlert> openAlertOpt = driftAlertRepository.findFirstByParserNameAndStatus(parserName, "OPEN");
            if (openAlertOpt.isEmpty()) {
                String reason = confidenceBreach
                        ? String.format("Confidence dropped by %.1f%% (baseline: %.2f, rolling: %.2f)", confidenceDrop * 100, baseline, currentConfidence)
                        : String.format("Success rate dropped to %.1f%% below threshold %.1f%%", successRate * 100, successRateThreshold * 100);

                DriftAlert alert = DriftAlert.builder()
                        .parserName(parserName)
                        .parserVersion(parser.getVersion())
                        .baselineConfidence(baseline)
                        .currentConfidence(currentConfidence)
                        .confidenceDrop(confidenceDrop)
                        .successRate(successRate)
                        .totalEvents(recentEvents.size())
                        .dlqEvents((int) dlqCount)
                        .status("OPEN")
                        .detectedAt(Instant.now())
                        .details("Parser quality drift detected: " + reason)
                        .build();

                driftAlertRepository.save(alert);

                // Broadcast alert over /topic/alerts
                Map<String, Object> alertPayload = new LinkedHashMap<>();
                alertPayload.put("alertType", "PARSER_DRIFT");
                alertPayload.put("id", alert.getId());
                alertPayload.put("parserName", parserName);
                alertPayload.put("parserVersion", parser.getVersion());
                alertPayload.put("baselineConfidence", baseline);
                alertPayload.put("currentConfidence", currentConfidence);
                alertPayload.put("confidenceDrop", confidenceDrop);
                alertPayload.put("successRate", successRate);
                alertPayload.put("status", "OPEN");
                alertPayload.put("details", alert.getDetails());
                alertPayload.put("detectedAt", alert.getDetectedAt().toString());

                metricsBroadcaster.broadcastAlert(alertPayload);
                log.warn("RAISED DRIFT ALERT for parser {}: {}", parserName, reason);
                return Optional.of(alert);
            }
        }

        return Optional.empty();
    }

    public ParserDriftMetricsDto getParserDriftMetrics(String parserName) {
        Optional<ParserPlugin> pluginOpt = parserRegistry.getParser(parserName);
        double baseline = 0.95;
        String version = "1.0.0";
        String formatType = "CUSTOM";

        if (pluginOpt.isPresent()) {
            ParserPlugin plugin = pluginOpt.get();
            baseline = getParserBaselineConfidence(plugin);
            version = plugin.getVersion();
            formatType = plugin.getFormatType();
        }

        List<NormalizedEvent> recentEvents = normalizedEventRepository.findTop500ByParserNameOrderByProcessedAtDesc(parserName);
        double currentConfidence = recentEvents.isEmpty() ? baseline : recentEvents.stream()
                .mapToDouble(e -> e.getAverageConfidence() != null ? e.getAverageConfidence() : 0.8)
                .average()
                .orElse(baseline);

        Instant cutoff = Instant.now().minus(Duration.ofHours(24));
        long dlqCount = dlqEntryRepository.countByDetectedFormatAndCreatedAtAfter(formatType, cutoff);
        long successCount = recentEvents.size();
        double successRate = (successCount + dlqCount > 0)
                ? (double) successCount / (successCount + dlqCount)
                : 1.0;

        double drop = Math.max(0.0, baseline - currentConfidence);

        Optional<DriftAlert> openAlert = driftAlertRepository.findFirstByParserNameAndStatus(parserName, "OPEN");
        boolean hasAlert = openAlert.isPresent();

        String health = "HEALTHY";
        if (hasAlert || drop >= confidenceDropThreshold || successRate < successRateThreshold) {
            health = "DRIFT_ALERT";
        } else if (drop >= (confidenceDropThreshold / 2.0)) {
            health = "WARNING";
        }

        // Chronological sparkline samples (last 20 points)
        List<Double> history = recentEvents.stream()
                .limit(20)
                .map(e -> e.getAverageConfidence() != null ? e.getAverageConfidence() : 0.85)
                .collect(Collectors.toList());
        Collections.reverse(history);

        return ParserDriftMetricsDto.builder()
                .parserName(parserName)
                .parserVersion(version)
                .formatType(formatType)
                .baselineConfidence(baseline)
                .currentConfidence(currentConfidence)
                .confidenceDrop(drop)
                .successRate(successRate)
                .sampleCount(recentEvents.size())
                .dlqCount(dlqCount)
                .healthStatus(health)
                .activeAlert(hasAlert)
                .confidenceHistory(history)
                .lastChecked(Instant.now())
                .build();
    }

    private double getParserBaselineConfidence(ParserPlugin parser) {
        Optional<ParserEntity> entityOpt = parserEntityRepository.findByName(parser.getName());
        if (entityOpt.isPresent()) {
            Optional<ParserVersion> pvOpt = parserVersionRepository.findByParserIdAndActiveTrue(entityOpt.get().getId());
            if (pvOpt.isPresent() && pvOpt.get().getAverageConfidence() != null) {
                return pvOpt.get().getAverageConfidence();
            }
        }
        if (parser instanceof DynamicGeneratedParser dgp) {
            return dgp.getConfidenceScore() > 0 ? dgp.getConfidenceScore() : 0.90;
        }
        return 0.95;
    }

    @Transactional
    public Optional<DriftAlert> acknowledgeAlert(Long alertId, String username) {
        Optional<DriftAlert> alertOpt = driftAlertRepository.findById(alertId);
        if (alertOpt.isPresent()) {
            DriftAlert alert = alertOpt.get();
            alert.setStatus("ACKNOWLEDGED");
            alert.setAcknowledgedAt(Instant.now());
            alert.setAcknowledgedBy(username != null ? username : "OPERATOR");
            driftAlertRepository.save(alert);
            return Optional.of(alert);
        }
        return Optional.empty();
    }

    public List<DriftAlert> listAlerts(String status) {
        if (status != null && !status.isBlank()) {
            return driftAlertRepository.findByStatusOrderByDetectedAtDesc(status.toUpperCase());
        }
        return driftAlertRepository.findAllByOrderByDetectedAtDesc();
    }
}
