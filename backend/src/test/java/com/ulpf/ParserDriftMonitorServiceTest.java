package com.ulpf;

import com.ulpf.domain.DriftAlert;
import com.ulpf.domain.NormalizedEvent;
import com.ulpf.parsers.DynamicParserRegistry;
import com.ulpf.parsers.ParserPlugin;
import com.ulpf.parsers.monitoring.ParserDriftMonitorService;
import com.ulpf.repository.DlqEntryRepository;
import com.ulpf.repository.DriftAlertRepository;
import com.ulpf.repository.NormalizedEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("dev")
public class ParserDriftMonitorServiceTest {

    @Autowired
    private ParserDriftMonitorService driftMonitorService;

    @Autowired
    private NormalizedEventRepository normalizedEventRepository;

    @Autowired
    private DriftAlertRepository driftAlertRepository;

    @Autowired
    private DlqEntryRepository dlqEntryRepository;

    @Autowired
    private DynamicParserRegistry parserRegistry;

    @BeforeEach
    void setUp() {
        driftAlertRepository.deleteAll();
        normalizedEventRepository.deleteAll();
        dlqEntryRepository.deleteAll();
    }

    @Test
    @DisplayName("Should prevent false breach alerts when success rate is 100% and DLQ is 0")
    void testPreventFalseBreachAlertsWhenSuccessRateIs100() {
        String parserName = "syslog_rfc_parser";
        ParserPlugin parser = parserRegistry.getParser(parserName).orElseThrow();

        // Events with slightly lower confidence (e.g. 0.78 vs baseline 0.95 -> 0.17 drop) but 100% success and 0 DLQ
        for (int i = 0; i < 20; i++) {
            NormalizedEvent evt = NormalizedEvent.builder()
                    .eventId("EVT-CLEAN-" + i)
                    .rawEventId("RAW-CLEAN-" + i)
                    .rawHashSha256("hash-" + i)
                    .timestampUtc(Instant.now().minusSeconds(i * 10))
                    .parserName(parserName)
                    .parserVersion(parser.getVersion())
                    .format(parser.getFormatType())
                    .averageConfidence(0.78)
                    .ocsfJson("{}")
                    .processedAt(Instant.now().minusSeconds(i * 10))
                    .build();
            normalizedEventRepository.save(evt);
        }

        Optional<DriftAlert> alertOpt = driftMonitorService.evaluateParserDrift(parser);
        assertTrue(alertOpt.isEmpty(), "Should NOT raise drift breach when success rate is 100% and DLQ count is 0");

        ParserDriftMonitorService.ParserDriftMetricsDto metrics = driftMonitorService.getParserDriftMetrics(parserName);
        assertNotNull(metrics);
        assertFalse(metrics.isActiveAlert());
        assertEquals("WARNING", metrics.getHealthStatus()); // Degraded warning but not a breach
    }

    @Test
    @DisplayName("Should detect parser drift and raise alert when confidence drops and DLQ failures occur")
    void testParserDriftDetectionOnConfidenceDropWithFailures() {
        String parserName = "syslog_rfc_parser";
        ParserPlugin parser = parserRegistry.getParser(parserName).orElseThrow();

        // Feed synthetic sequence of events with degraded average confidence
        for (int i = 0; i < 20; i++) {
            NormalizedEvent evt = NormalizedEvent.builder()
                    .eventId("EVT-DRIFT-" + i)
                    .rawEventId("RAW-DRIFT-" + i)
                    .rawHashSha256("hash-" + i)
                    .timestampUtc(Instant.now().minusSeconds(i * 10))
                    .parserName(parserName)
                    .parserVersion(parser.getVersion())
                    .format(parser.getFormatType())
                    .averageConfidence(0.65) // Degraded confidence
                    .ocsfJson("{}")
                    .processedAt(Instant.now().minusSeconds(i * 10))
                    .build();
            normalizedEventRepository.save(evt);
        }

        // Add DLQ failure to trigger breach
        com.ulpf.domain.DlqEntry dlq = com.ulpf.domain.DlqEntry.builder()
                .rawEventId("RAW-FAIL-01")
                .rawMessage("<13>Unparseable corrupt payload")
                .detectedFormat(parser.getFormatType())
                .failureCode("PARSE_EXCEPTION")
                .failureReason("Syntax mismatch")
                .status("QUARANTINED")
                .createdAt(Instant.now().minusSeconds(30))
                .build();
        dlqEntryRepository.save(dlq);

        // Trigger drift evaluation
        Optional<DriftAlert> alertOpt = driftMonitorService.evaluateParserDrift(parser);

        assertTrue(alertOpt.isPresent(), "Expected DriftAlert to be raised for degraded parser with failures");
        DriftAlert alert = alertOpt.get();
        assertEquals(parserName, alert.getParserName());
        assertEquals("OPEN", alert.getStatus());
        assertTrue(alert.getConfidenceDrop() >= 0.15);

        // Check metrics DTO
        ParserDriftMonitorService.ParserDriftMetricsDto metrics = driftMonitorService.getParserDriftMetrics(parserName);
        assertNotNull(metrics);
        assertEquals("DRIFT_ALERT", metrics.getHealthStatus());
        assertTrue(metrics.isActiveAlert());
    }
}
