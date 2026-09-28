package com.ulpf;

import com.ulpf.correlation.NarrativeBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class NarrativeBuilderTest {

    private final NarrativeBuilder narrativeBuilder = new NarrativeBuilder();

    @Test
    @DisplayName("Should generate stable narrative and verbatim assert non-overclaiming hypothesis framing")
    void testNarrativeGenerationAndVerbatimDisclaimer() {
        String entityIp = "192.168.1.150";

        Instant t1 = Instant.parse("2026-08-30T10:00:00Z");
        Instant t2 = Instant.parse("2026-08-30T10:12:00Z");
        Instant t3 = Instant.parse("2026-08-30T10:25:00Z");

        List<NarrativeBuilder.CorrelatedEventSummary> events = List.of(
                NarrativeBuilder.CorrelatedEventSummary.builder()
                        .eventId("EVT-001")
                        .ruleTitle("SSH Brute Force Authentication Failure")
                        .techniqueId("T1110")
                        .tactic("Credential Access")
                        .timestamp(t1)
                        .severity("high")
                        .build(),
                NarrativeBuilder.CorrelatedEventSummary.builder()
                        .eventId("EVT-002")
                        .ruleTitle("Network Service Discovery and Port Scanning")
                        .techniqueId("T1046")
                        .tactic("Discovery")
                        .timestamp(t2)
                        .severity("medium")
                        .build(),
                NarrativeBuilder.CorrelatedEventSummary.builder()
                        .eventId("EVT-003")
                        .ruleTitle("DNS Tunneling or Exfiltration Query Burst")
                        .techniqueId("T1048")
                        .tactic("Exfiltration")
                        .timestamp(t3)
                        .severity("critical")
                        .build()
        );

        String narrative = narrativeBuilder.buildNarrative(entityIp, events);

        assertNotNull(narrative);
        assertTrue(narrative.startsWith("192.168.1.150 triggered 'SSH Brute Force Authentication Failure' (T1110, Credential Access) at 2026-08-30 10:00:00Z"));
        assertTrue(narrative.contains(", followed by 'Network Service Discovery and Port Scanning' (T1046, Discovery) at 2026-08-30 10:12:00Z"));
        assertTrue(narrative.contains(", followed by 'DNS Tunneling or Exfiltration Query Burst' (T1048, Exfiltration) at 2026-08-30 10:25:00Z"));

        // Verbatim assertion for non-overclaiming hypothesis framing
        String expectedSuffix = " — pattern consistent with a multi-stage attack; probable initiating event is the first entry above (heuristic hypothesis, not a proven causal claim).";
        assertTrue(narrative.endsWith(expectedSuffix),
                "Narrative must conclude with verbatim non-overclaiming hypothesis framing");
    }
}
