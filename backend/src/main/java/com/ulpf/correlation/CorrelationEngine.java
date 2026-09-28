package com.ulpf.correlation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ulpf.domain.CorrelatedIncident;
import com.ulpf.domain.NormalizedEvent;
import com.ulpf.domain.SigmaMatch;
import com.ulpf.metrics.MetricsBroadcaster;
import com.ulpf.normalization.OcsfSchema;
import com.ulpf.repository.CorrelatedIncidentRepository;
import com.ulpf.repository.NormalizedEventRepository;
import com.ulpf.repository.SigmaMatchRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Auto Root-Cause Correlation Engine.
 * Correlates isolated Sigma detections and MITRE-tagged telemetry into multi-stage attack incidents.
 *
 * NOTE: The "root cause" is explicitly a heuristic hypothesis (the earliest observed event in the chain),
 * not a proven causal claim.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CorrelationEngine {

    private final CorrelatedIncidentRepository incidentRepository;
    private final SigmaMatchRepository sigmaMatchRepository;
    private final NormalizedEventRepository normalizedEventRepository;
    private final MetricsBroadcaster metricsBroadcaster;
    private final NarrativeBuilder narrativeBuilder = new NarrativeBuilder();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${ulpf.correlation.enabled:true}")
    private boolean enabled;

    @Value("${ulpf.correlation.window-minutes:30}")
    private int windowMinutes;

    @Scheduled(fixedDelayString = "${ulpf.correlation.check-interval-ms:120000}")
    public void scheduledCorrelationScan() {
        if (!enabled) return;
        try {
            correlateWindow(windowMinutes);
        } catch (Exception e) {
            log.error("Error running automated correlation scan: {}", e.getMessage(), e);
        }
    }

    /**
     * Executes correlation scan over a given sliding window (in minutes).
     *
     * @param minutes sliding window duration in minutes
     * @return list of newly created or updated incidents
     */
    @Transactional
    public List<CorrelatedIncident> correlateWindow(int minutes) {
        Instant windowStart = Instant.now().minus(minutes, ChronoUnit.MINUTES);
        log.debug("Running correlation engine scan since {}", windowStart);

        // 1. Pull Sigma matches in window
        List<SigmaMatch> matches = sigmaMatchRepository.findByMatchedAtAfter(windowStart);

        // 2. Pull Normalized events in window
        List<NormalizedEvent> normEvents = normalizedEventRepository.findByProcessedAtAfter(windowStart);

        // 3. Unify detections into CorrelatedEventSummary objects
        List<NarrativeBuilder.CorrelatedEventSummary> unifiedEvents = new ArrayList<>();
        Map<String, String> eventToIpMap = new HashMap<>();
        Map<String, String> eventToUserMap = new HashMap<>();

        for (SigmaMatch m : matches) {
            unifiedEvents.add(NarrativeBuilder.CorrelatedEventSummary.builder()
                    .eventId(m.getEventId())
                    .ruleTitle(m.getRuleTitle())
                    .techniqueId(m.getTechniqueId())
                    .tactic(m.getTactic())
                    .timestamp(m.getMatchedAt())
                    .severity(m.getSeverity())
                    .build());

            if (m.getSourceIp() != null && !m.getSourceIp().isBlank()) {
                eventToIpMap.put(m.getEventId(), m.getSourceIp());
            }
        }

        for (NormalizedEvent ne : normEvents) {
            if (ne.getSourceIp() != null && !ne.getSourceIp().isBlank()) {
                eventToIpMap.put(ne.getEventId(), ne.getSourceIp());
            }

            try {
                if (ne.getOcsfJson() != null && !ne.getOcsfJson().isBlank()) {
                    OcsfSchema ocsf = objectMapper.readValue(ne.getOcsfJson(), OcsfSchema.class);
                    if (ocsf.getSource() != null && ocsf.getSource().getUser() != null && !ocsf.getSource().getUser().isBlank()) {
                        eventToUserMap.put(ne.getEventId(), ocsf.getSource().getUser());
                    } else if (ocsf.getExtensions() != null && ocsf.getExtensions().containsKey("user")) {
                        eventToUserMap.put(ne.getEventId(), String.valueOf(ocsf.getExtensions().get("user")));
                    }

                    if (ocsf.getThreat() != null && ocsf.getThreat().getMitreTechniqueId() != null) {
                        // Check if already captured via SigmaMatch
                        boolean exists = unifiedEvents.stream().anyMatch(e -> e.getEventId().equals(ne.getEventId()));
                        if (!exists) {
                            unifiedEvents.add(NarrativeBuilder.CorrelatedEventSummary.builder()
                                    .eventId(ne.getEventId())
                                    .ruleTitle(ocsf.getThreat().getMitreTechniqueName() != null ? ocsf.getThreat().getMitreTechniqueName() : "MITRE Technique " + ocsf.getThreat().getMitreTechniqueId())
                                    .techniqueId(ocsf.getThreat().getMitreTechniqueId())
                                    .tactic(ocsf.getThreat().getMitreTactic())
                                    .timestamp(ne.getTimestampUtc())
                                    .severity(ne.getSeverity())
                                    .build());
                        }
                    }
                }
            } catch (Exception ignored) {}
        }

        // 4. Group by Source IP and separately by Source User
        Map<String, List<NarrativeBuilder.CorrelatedEventSummary>> ipGroups = new HashMap<>();
        Map<String, List<NarrativeBuilder.CorrelatedEventSummary>> userGroups = new HashMap<>();

        for (NarrativeBuilder.CorrelatedEventSummary evt : unifiedEvents) {
            String ip = eventToIpMap.get(evt.getEventId());
            if (ip != null && !ip.isBlank() && !ip.equalsIgnoreCase("unknown")) {
                ipGroups.computeIfAbsent(ip, k -> new ArrayList<>()).add(evt);
            }

            String user = eventToUserMap.get(evt.getEventId());
            if (user != null && !user.isBlank() && !user.equalsIgnoreCase("unknown")) {
                userGroups.computeIfAbsent(user, k -> new ArrayList<>()).add(evt);
            }
        }

        List<CorrelatedIncident> processedIncidents = new ArrayList<>();

        // Process IP-based correlations
        for (Map.Entry<String, List<NarrativeBuilder.CorrelatedEventSummary>> entry : ipGroups.entrySet()) {
            processGroup(entry.getKey(), "IP", entry.getValue(), windowStart).ifPresent(processedIncidents::add);
        }

        // Process User-based correlations
        for (Map.Entry<String, List<NarrativeBuilder.CorrelatedEventSummary>> entry : userGroups.entrySet()) {
            processGroup(entry.getKey(), "USER", entry.getValue(), windowStart).ifPresent(processedIncidents::add);
        }

        return processedIncidents;
    }

    /**
     * Evaluates a group of events for promotion into a CorrelatedIncident.
     */
    public Optional<CorrelatedIncident> processGroup(String correlationKey,
                                                     String keyType,
                                                     List<NarrativeBuilder.CorrelatedEventSummary> groupEvents,
                                                     Instant windowStart) {
        if (groupEvents == null || groupEvents.isEmpty()) {
            return Optional.empty();
        }

        // Filter events strictly within windowStart
        List<NarrativeBuilder.CorrelatedEventSummary> inWindow = groupEvents.stream()
                .filter(e -> e.getTimestamp() != null && !e.getTimestamp().isBefore(windowStart))
                .collect(Collectors.toList());

        if (inWindow.isEmpty()) {
            return Optional.empty();
        }

        // Calculate distinct MITRE tactics
        Set<String> distinctTactics = inWindow.stream()
                .map(NarrativeBuilder.CorrelatedEventSummary::getTactic)
                .filter(Objects::nonNull)
                .map(MitreTacticOrder::canonicalize)
                .collect(Collectors.toSet());

        // PROMOTION THRESHOLD: Must span >= 2 distinct MITRE tactics
        if (distinctTactics.size() < 2) {
            log.debug("Skipping correlation for {}: spans {} tactics (< 2 required)", correlationKey, distinctTactics.size());
            return Optional.empty();
        }

        // Sort events chronologically to determine root event (earliest timestamp)
        inWindow.sort(Comparator.comparing(NarrativeBuilder.CorrelatedEventSummary::getTimestamp));
        NarrativeBuilder.CorrelatedEventSummary rootEvent = inWindow.get(0);
        Instant firstSeen = inWindow.get(0).getTimestamp();
        Instant lastSeen = inWindow.get(inWindow.size() - 1).getTimestamp();

        // Sort tactics according to MITRE kill-chain order for narrative & timeline
        List<String> orderedTacticChain = new ArrayList<>(distinctTactics);
        orderedTacticChain.sort(MitreTacticOrder.comparator());

        // Calculate severity
        List<String> severities = inWindow.stream()
                .map(NarrativeBuilder.CorrelatedEventSummary::getSeverity)
                .collect(Collectors.toList());
        String calculatedSeverity = calculateSeverity(severities, distinctTactics.size());

        // Build structured narrative text
        String narrativeText = narrativeBuilder.buildNarrative(correlationKey, inWindow);

        List<String> memberEventIds = inWindow.stream()
                .map(NarrativeBuilder.CorrelatedEventSummary::getEventId)
                .distinct()
                .collect(Collectors.toList());

        String memberEventIdsJson;
        String tacticChainJson;
        try {
            memberEventIdsJson = objectMapper.writeValueAsString(memberEventIds);
            tacticChainJson = objectMapper.writeValueAsString(orderedTacticChain);
        } catch (Exception e) {
            memberEventIdsJson = "[]";
            tacticChainJson = "[]";
        }

        // Check for existing active incident to deduplicate / update
        Optional<CorrelatedIncident> existingOpt =
                incidentRepository.findFirstByCorrelationKeyAndStatusNotOrderByLastSeenAtDesc(correlationKey, "CLOSED");

        CorrelatedIncident incident;
        if (existingOpt.isPresent()) {
            incident = existingOpt.get();
            incident.setRootEventId(rootEvent.getEventId());
            incident.setMemberEventIds(memberEventIdsJson);
            incident.setTacticChain(tacticChainJson);
            incident.setNarrativeText(narrativeText);
            incident.setSeverity(calculatedSeverity);
            incident.setDistinctTacticCount(distinctTactics.size());
            incident.setEventCount(memberEventIds.size());
            incident.setFirstSeenAt(firstSeen.isBefore(incident.getFirstSeenAt()) ? firstSeen : incident.getFirstSeenAt());
            incident.setLastSeenAt(lastSeen.isAfter(incident.getLastSeenAt()) ? lastSeen : incident.getLastSeenAt());
            incident.setUpdatedAt(Instant.now());
        } else {
            String incidentKey = "INC-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
            incident = CorrelatedIncident.builder()
                    .incidentKey(incidentKey)
                    .correlationKey(correlationKey)
                    .keyType(keyType)
                    .rootEventId(rootEvent.getEventId())
                    .memberEventIds(memberEventIdsJson)
                    .tacticChain(tacticChainJson)
                    .narrativeText(narrativeText)
                    .severity(calculatedSeverity)
                    .status("OPEN")
                    .distinctTacticCount(distinctTactics.size())
                    .eventCount(memberEventIds.size())
                    .firstSeenAt(firstSeen)
                    .lastSeenAt(lastSeen)
                    .createdAt(Instant.now())
                    .updatedAt(Instant.now())
                    .build();
        }

        CorrelatedIncident saved = incidentRepository.save(incident);

        // Broadcast to unified alert channel
        Map<String, Object> alertPayload = new LinkedHashMap<>();
        alertPayload.put("alertType", "CORRELATED_INCIDENT");
        alertPayload.put("type", "incident");
        alertPayload.put("id", saved.getId());
        alertPayload.put("incidentKey", saved.getIncidentKey());
        alertPayload.put("correlationKey", saved.getCorrelationKey());
        alertPayload.put("keyType", saved.getKeyType());
        alertPayload.put("severity", saved.getSeverity());
        alertPayload.put("status", saved.getStatus());
        alertPayload.put("distinctTacticCount", saved.getDistinctTacticCount());
        alertPayload.put("eventCount", saved.getEventCount());
        alertPayload.put("rootEventId", saved.getRootEventId());
        alertPayload.put("narrative", saved.getNarrativeText());
        alertPayload.put("detectedAt", saved.getLastSeenAt().toString());

        metricsBroadcaster.broadcastAlert(alertPayload);

        log.info("Correlated Incident {}: entity={}, tactics={}, events={}, severity={}",
                saved.getIncidentKey(), correlationKey, distinctTactics.size(), memberEventIds.size(), saved.getSeverity());

        return Optional.of(saved);
    }

    /**
     * Concrete reproducible severity formula:
     * 1. Base score = highest severity among member alerts:
     *    CRITICAL (4), HIGH (3), MEDIUM (2), LOW (1), INFORMATIONAL (0).
     * 2. If distinctTacticCount >= 4: escalate score by +1 (capped at CRITICAL / 4).
     * 3. If distinctTacticCount >= 3 and base score <= 1: escalate to MEDIUM (2).
     */
    public static String calculateSeverity(List<String> severities, int distinctTacticCount) {
        int maxScore = 1; // Default LOW
        if (severities != null) {
            for (String sev : severities) {
                if (sev == null) continue;
                switch (sev.trim().toUpperCase()) {
                    case "CRITICAL" -> maxScore = Math.max(maxScore, 4);
                    case "HIGH" -> maxScore = Math.max(maxScore, 3);
                    case "MEDIUM" -> maxScore = Math.max(maxScore, 2);
                    case "LOW" -> maxScore = Math.max(maxScore, 1);
                    case "INFORMATIONAL" -> maxScore = Math.max(maxScore, 0);
                }
            }
        }

        if (distinctTacticCount >= 4) {
            maxScore = Math.min(4, maxScore + 1);
        } else if (distinctTacticCount >= 3 && maxScore <= 1) {
            maxScore = 2;
        }

        return switch (maxScore) {
            case 4 -> "CRITICAL";
            case 3 -> "HIGH";
            case 2 -> "MEDIUM";
            default -> "LOW";
        };
    }
}
