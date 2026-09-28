package com.ulpf.correlation;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Isolated deterministic narrative generator for correlated multi-stage security incidents.
 * Produces structured template text with explicit heuristic hypothesis framing.
 */
public class NarrativeBuilder {

    private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss'Z'")
            .withZone(ZoneOffset.UTC);

    public static final String NARRATIVE_DISCLAIMER_SUFFIX =
            " — pattern consistent with a multi-stage attack; probable initiating event is the first entry above (heuristic hypothesis, not a proven causal claim).";

    @Data
    @Builder
    public static class CorrelatedEventSummary {
        private String eventId;
        private String ruleTitle;
        private String techniqueId;
        private String tactic;
        private Instant timestamp;
        private String severity;
    }

    /**
     * Builds deterministic narrative string from a chronological sequence of correlated detection events.
     *
     * @param correlationKey entity identifier (e.g. IP address or username)
     * @param events list of member events
     * @return structured narrative text
     */
    public String buildNarrative(String correlationKey, List<CorrelatedEventSummary> events) {
        if (events == null || events.isEmpty()) {
            return correlationKey + " associated with indeterminate events" + NARRATIVE_DISCLAIMER_SUFFIX;
        }

        // Sort events chronologically to describe chronological attack evolution
        List<CorrelatedEventSummary> chronological = new ArrayList<>(events);
        chronological.sort(Comparator.comparing(CorrelatedEventSummary::getTimestamp));

        StringBuilder sb = new StringBuilder();
        sb.append(correlationKey).append(" triggered ");

        for (int i = 0; i < chronological.size(); i++) {
            CorrelatedEventSummary evt = chronological.get(i);
            if (i > 0) {
                sb.append(", followed by ");
            }

            String title = evt.getRuleTitle() != null && !evt.getRuleTitle().isBlank()
                    ? evt.getRuleTitle()
                    : "Security Telemetry Event";
            String tech = evt.getTechniqueId() != null && !evt.getTechniqueId().isBlank()
                    ? evt.getTechniqueId()
                    : "Unknown Technique";
            String tactic = MitreTacticOrder.canonicalize(evt.getTactic());
            String timeStr = evt.getTimestamp() != null ? TIME_FORMATTER.format(evt.getTimestamp()) : "unknown time";

            sb.append("'").append(title).append("' (").append(tech).append(", ").append(tactic)
                    .append(") at ").append(timeStr);
        }

        sb.append(NARRATIVE_DISCLAIMER_SUFFIX);
        return sb.toString();
    }
}
