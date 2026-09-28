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
    @DisplayName("Should detect parser drift and raise alert when confidence drops significantly below baseline")
    void testParserDriftDetectionOnConfidenceDrop() {
        String parserName = "syslog_rfc_parser";
        ParserPlugin parser = parserRegistry.getParser(parserName).orElseThrow();

        // Feed synthetic sequence of events with degraded average confidence (0.65 vs baseline 0.95 -> 0.30 drop > 0.15 threshold)
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

        // Trigger drift evaluation
        Optional<DriftAlert> alertOpt = driftMonitorService.evaluateParserDrift(parser);

        assertTrue(alertOpt.isPresent(), "Expected DriftAlert to be raised for degraded parser");
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
