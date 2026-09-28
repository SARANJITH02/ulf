package com.ulpf;

import com.ulpf.correlation.CorrelationEngine;
import com.ulpf.correlation.MitreTacticOrder;
import com.ulpf.correlation.NarrativeBuilder;
import com.ulpf.domain.CorrelatedIncident;
import com.ulpf.domain.NormalizedEvent;
import com.ulpf.domain.SigmaMatch;
import com.ulpf.repository.CorrelatedIncidentRepository;
import com.ulpf.repository.NormalizedEventRepository;
import com.ulpf.repository.SigmaMatchRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("dev")
public class CorrelationEngineTest {

    @Autowired
    private CorrelationEngine correlationEngine;

    @Autowired
    private CorrelatedIncidentRepository incidentRepository;

    @Autowired
    private SigmaMatchRepository sigmaMatchRepository;

    @Autowired
    private NormalizedEventRepository normalizedEventRepository;

    @BeforeEach
    void setUp() {
        incidentRepository.deleteAll();
        sigmaMatchRepository.deleteAll();
        normalizedEventRepository.deleteAll();
    }

    @Test
    @DisplayName("Case 1: Promotion — Spans >=2 distinct MITRE tactics -> CorrelatedIncident created with kill-chain ordered tactics")
    void testPromotionCase_MultiTacticChain() {
        String attackerIp = "192.168.1.105";
        Instant now = Instant.now();

        // 1. Discovery (T1046)
        SigmaMatch m1 = SigmaMatch.builder()
                .eventId("EVT-DISC-01")
                .ruleId("SIGMA-T1046-SCAN-001")
                .ruleTitle("Network Service Discovery and Port Scanning")
                .severity("medium")
                .techniqueId("T1046")
                .tactic("Discovery")
                .sourceIp(attackerIp)
                .matchedAt(now.minus(15, ChronoUnit.MINUTES))
                .build();

        // 2. Credential Access (T1110)
        SigmaMatch m2 = SigmaMatch.builder()
                .eventId("EVT-CRED-02")
                .ruleId("SIGMA-T1110-SSH-001")
                .ruleTitle("SSH Brute Force Authentication Failure")
                .severity("high")
                .techniqueId("T1110")
                .tactic("Credential Access")
                .sourceIp(attackerIp)
                .matchedAt(now.minus(10, ChronoUnit.MINUTES))
                .build();

        // 3. Exfiltration (T1048)
        SigmaMatch m3 = SigmaMatch.builder()
                .eventId("EVT-EXFIL-03")
                .ruleId("SIGMA-T1048-DNS-001")
                .ruleTitle("DNS Tunneling or Exfiltration Query Burst")
                .severity("critical")
                .techniqueId("T1048")
                .tactic("Exfiltration")
                .sourceIp(attackerIp)
                .matchedAt(now.minus(2, ChronoUnit.MINUTES))
                .build();

        sigmaMatchRepository.saveAll(List.of(m1, m2, m3));

        List<CorrelatedIncident> incidents = correlationEngine.correlateWindow(30);

        assertEquals(1, incidents.size(), "Expected 1 correlated incident promoted");
        CorrelatedIncident incident = incidents.get(0);

        assertEquals(attackerIp, incident.getCorrelationKey());
        assertEquals("IP", incident.getKeyType());
        assertEquals("EVT-DISC-01", incident.getRootEventId(), "Earliest event must be the root event");
        assertEquals(3, incident.getDistinctTacticCount());
        assertEquals(3, incident.getEventCount());
        assertEquals("CRITICAL", incident.getSeverity());

        // Verify tacticChain is in MITRE kill-chain order (Credential Access -> Discovery -> Exfiltration)
        String tacticChain = incident.getTacticChain();
        assertTrue(tacticChain.indexOf("Credential Access") < tacticChain.indexOf("Discovery"));
        assertTrue(tacticChain.indexOf("Discovery") < tacticChain.indexOf("Exfiltration"));
    }

    @Test
    @DisplayName("Case 2: Non-promotion — Repeated events on same tactic (e.g. 50 SSH brute force hits) must NOT create incident")
    void testNonPromotionCase_SingleTacticRepetition() {
        String noisyIp = "192.168.1.200";
        Instant now = Instant.now();

        List<SigmaMatch> singleTacticHits = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            singleTacticHits.add(SigmaMatch.builder()
                    .eventId("EVT-SSH-" + i)
                    .ruleId("SIGMA-T1110-SSH-001")
                    .ruleTitle("SSH Brute Force Authentication Failure")
                    .severity("high")
                    .techniqueId("T1110")
                    .tactic("Credential Access") // Same tactic for all 50 events
                    .sourceIp(noisyIp)
                    .matchedAt(now.minus(i * 20, ChronoUnit.SECONDS))
                    .build());
        }

        sigmaMatchRepository.saveAll(singleTacticHits);

        List<CorrelatedIncident> incidents = correlationEngine.correlateWindow(30);

        assertEquals(0, incidents.size(), "Single tactic events must NOT be promoted to an incident, regardless of volume");
        assertEquals(0, incidentRepository.count());
    }

    @Test
    @DisplayName("Case 3: Window-boundary — Events spanning >30m gap excluded; events within 30m window included")
    void testWindowBoundaryExclusionAndInclusion() {
        String entityIp = "192.168.1.250";
        Instant now = Instant.now();

        // 1. Outside window (> 30m ago) -> Discovery
        SigmaMatch oldEvent = SigmaMatch.builder()
                .eventId("EVT-OLD-DISC")
                .ruleId("SIGMA-T1046-SCAN-001")
                .ruleTitle("Network Service Discovery and Port Scanning")
                .severity("medium")
                .techniqueId("T1046")
                .tactic("Discovery")
                .sourceIp(entityIp)
                .matchedAt(now.minus(45, ChronoUnit.MINUTES)) // Gap outside 30m
                .build();

        // 2. Inside window (10m ago) -> SSH Brute Force
        SigmaMatch recentEvent = SigmaMatch.builder()
                .eventId("EVT-RECENT-SSH")
                .ruleId("SIGMA-T1110-SSH-001")
                .ruleTitle("SSH Brute Force Authentication Failure")
                .severity("high")
                .techniqueId("T1110")
                .tactic("Credential Access")
                .sourceIp(entityIp)
                .matchedAt(now.minus(10, ChronoUnit.MINUTES))
                .build();

        sigmaMatchRepository.saveAll(List.of(oldEvent, recentEvent));

        // When scanning a 30m window, only EVT-RECENT-SSH is in window -> spans only 1 tactic -> NO incident
        List<CorrelatedIncident> incidents30m = correlationEngine.correlateWindow(30);
        assertEquals(0, incidents30m.size(), "Old event outside window boundary must be excluded");

        // When scanning a 60m window, both events are included -> spans 2 tactics -> INCIDENT PROMOTED
        List<CorrelatedIncident> incidents60m = correlationEngine.correlateWindow(60);
        assertEquals(1, incidents60m.size(), "When both events fall inside window, incident must be created");
    }

    @Test
    @DisplayName("Case 4: Root-event selection — Out of order arrival guarantees rootEventId is earliest by timestampUtc")
    void testRootEventSelection_OutOfOrderArrival() {
        String entityIp = "192.168.1.99";
        Instant now = Instant.now();

        Instant tEarliest = now.minus(20, ChronoUnit.MINUTES);
        Instant tMiddle = now.minus(12, ChronoUnit.MINUTES);
        Instant tLatest = now.minus(2, ChronoUnit.MINUTES);

        // Feed events intentionally out of chronological order (Latest first, then Middle, then Earliest)
        SigmaMatch mLatest = SigmaMatch.builder()
                .eventId("EVT-LATEST")
                .ruleId("SIGMA-T1048-DNS-001")
                .ruleTitle("DNS Tunneling")
                .severity("high")
                .techniqueId("T1048")
                .tactic("Exfiltration")
                .sourceIp(entityIp)
                .matchedAt(tLatest)
                .build();

        SigmaMatch mMiddle = SigmaMatch.builder()
                .eventId("EVT-MIDDLE")
                .ruleId("SIGMA-T1071-C2PORT-001")
                .ruleTitle("C2 Port Traffic")
                .severity("medium")
                .techniqueId("T1071")
                .tactic("Command and Control")
                .sourceIp(entityIp)
                .matchedAt(tMiddle)
                .build();

        SigmaMatch mEarliest = SigmaMatch.builder()
                .eventId("EVT-EARLIEST-ROOT")
                .ruleId("SIGMA-T1046-SCAN-001")
                .ruleTitle("Port Scanning")
                .severity("low")
                .techniqueId("T1046")
                .tactic("Discovery")
                .sourceIp(entityIp)
                .matchedAt(tEarliest)
                .build();

        sigmaMatchRepository.save(mLatest);
        sigmaMatchRepository.save(mMiddle);
        sigmaMatchRepository.save(mEarliest);

        List<CorrelatedIncident> incidents = correlationEngine.correlateWindow(30);
        assertEquals(1, incidents.size());

        CorrelatedIncident incident = incidents.get(0);
        assertEquals("EVT-EARLIEST-ROOT", incident.getRootEventId(),
                "Root event must strictly be the earliest timestamped event, regardless of processing order");
        assertEquals(tEarliest.truncatedTo(ChronoUnit.MILLIS), incident.getFirstSeenAt().truncatedTo(ChronoUnit.MILLIS));
    }

    @Test
    @DisplayName("Case 5: Severity calculation formula and tactical escalation")
    void testIncidentSeverityCalculationAndEscalation() {
        // Base severity checks
        assertEquals("LOW", CorrelationEngine.calculateSeverity(List.of("low"), 2));
        assertEquals("MEDIUM", CorrelationEngine.calculateSeverity(List.of("low", "medium"), 2));
        assertEquals("HIGH", CorrelationEngine.calculateSeverity(List.of("medium", "high"), 2));
        assertEquals("CRITICAL", CorrelationEngine.calculateSeverity(List.of("high", "critical"), 2));

        // Tactical escalation: >= 4 distinct tactics escalates by +1 level
        assertEquals("HIGH", CorrelationEngine.calculateSeverity(List.of("medium"), 4),
                "4 distinct tactics must escalate MEDIUM (2) -> HIGH (3)");
        assertEquals("CRITICAL", CorrelationEngine.calculateSeverity(List.of("high"), 4),
                "4 distinct tactics must escalate HIGH (3) -> CRITICAL (4)");

        // 3 distinct tactics with low base escalates to MEDIUM
        assertEquals("MEDIUM", CorrelationEngine.calculateSeverity(List.of("low"), 3),
                "3 distinct tactics must escalate LOW -> MEDIUM");
    }
}
