package com.ulpf;

import com.ulpf.rules.SigmaRuleParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class SigmaRuleParserTest {

    private final SigmaRuleParser parser = new SigmaRuleParser();

    @Test
    @DisplayName("Should parse all bundled starter Sigma YAML rules successfully")
    void testParseAllBundledRules() throws Exception {
        PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
        Resource[] resources = resolver.getResources("classpath:sigma_rules/*.yml");

        assertTrue(resources.length >= 6, "Expected at least 6 bundled rules, found: " + resources.length);

        for (Resource res : resources) {
            try (InputStream is = res.getInputStream()) {
                String yaml = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                SigmaRuleParser.ParsedSigmaRule rule = parser.parse(yaml);

                assertNotNull(rule.getId(), "Rule ID missing in " + res.getFilename());
                assertNotNull(rule.getTitle(), "Rule title missing in " + res.getFilename());
                assertNotNull(rule.getSeverity(), "Severity missing in " + res.getFilename());
                assertNotNull(rule.getTechniqueId(), "Technique ID missing in " + res.getFilename());
                assertFalse(rule.getSelections().isEmpty(), "Selections empty in " + res.getFilename());
                assertNotNull(rule.getCondition(), "Condition missing in " + res.getFilename());
            }
        }
    }

    @Test
    @DisplayName("Should parse custom Sigma YAML with modifiers and condition expressions")
    void testParseCustomRuleWithModifiers() {
        String yaml = """
                title: Custom C2 Traffic Rule
                id: SIGMA-TEST-C2-999
                level: critical
                tags:
                  - attack.t1071
                  - attack.command_and_control
                detection:
                  selection_port:
                    destination.port: 4444
                  selection_payload:
                    raw.message|contains:
                      - "meterpreter"
                      - "beacon"
                  condition: selection_port and selection_payload
                """;

        SigmaRuleParser.ParsedSigmaRule rule = parser.parse(yaml);
        assertEquals("SIGMA-TEST-C2-999", rule.getId());
        assertEquals("critical", rule.getSeverity());
        assertEquals("T1071", rule.getTechniqueId());
        assertEquals("Command And Control", rule.getTactic());
        assertEquals(2, rule.getSelections().size());
        assertEquals("selection_port and selection_payload", rule.getCondition());

        SigmaRuleParser.SelectionBlock payloadBlock = rule.getSelections().get("selection_payload");
        assertNotNull(payloadBlock);
        assertEquals(SigmaRuleParser.Modifier.CONTAINS, payloadBlock.getCriteriaList().get(0).getModifier());
        assertEquals(2, payloadBlock.getCriteriaList().get(0).getExpectedValues().size());
    }
}
