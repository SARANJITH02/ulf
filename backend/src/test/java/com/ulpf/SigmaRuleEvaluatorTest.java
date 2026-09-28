package com.ulpf;

import com.ulpf.normalization.OcsfSchema;
import com.ulpf.rules.SigmaRuleEvaluator;
import com.ulpf.rules.SigmaRuleParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

public class SigmaRuleEvaluatorTest {

    private final SigmaRuleParser parser = new SigmaRuleParser();
    private final SigmaRuleEvaluator evaluator = new SigmaRuleEvaluator();

    @Test
    @DisplayName("Should evaluate and match SSH brute force rule on matching event")
    void testSshBruteForceEvaluationMatch() {
        String yaml = """
                title: SSH Brute Force Detection
                id: SIGMA-SSH-TEST-001
                level: high
                tags:
                  - attack.t1110
                  - attack.credential_access
                detection:
                  selection:
                    destination.port: 22
                    event.action:
                      - blocked
                      - denied
                  condition: selection
                """;

        SigmaRuleParser.ParsedSigmaRule rule = parser.parse(yaml);

        OcsfSchema matchingEvent = OcsfSchema.builder()
                .eventId("EVT-SSH-001")
                .destination(OcsfSchema.Endpoint.builder().ip("10.0.0.5").port(22).build())
                .event(OcsfSchema.EventDetail.builder().action("blocked").build())
                .build();

        Optional<OcsfSchema.SigmaMatchSummary> matchOpt = evaluator.evaluateRule(rule, matchingEvent);
        assertTrue(matchOpt.isPresent());
        assertEquals("SIGMA-SSH-TEST-001", matchOpt.get().getRuleId());
        assertEquals("high", matchOpt.get().getSeverity());
        assertEquals("T1110", matchOpt.get().getTechniqueId());
    }

    @Test
    @DisplayName("Should not match rule when conditions are not met")
    void testEvaluationNoMatch() {
        String yaml = """
                title: SSH Brute Force Detection
                id: SIGMA-SSH-TEST-001
                level: high
                detection:
                  selection:
                    destination.port: 22
                    event.action:
                      - blocked
                  condition: selection
                """;

        SigmaRuleParser.ParsedSigmaRule rule = parser.parse(yaml);

        // Port 80, Action allowed -> Should NOT match
        OcsfSchema nonMatchingEvent = OcsfSchema.builder()
                .eventId("EVT-WEB-001")
                .destination(OcsfSchema.Endpoint.builder().ip("10.0.0.5").port(80).build())
                .event(OcsfSchema.EventDetail.builder().action("allowed").build())
                .build();

        Optional<OcsfSchema.SigmaMatchSummary> matchOpt = evaluator.evaluateRule(rule, nonMatchingEvent);
        assertFalse(matchOpt.isPresent());
    }
}
