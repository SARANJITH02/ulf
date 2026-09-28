package com.ulpf.rules;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Pattern;

@Component
@Slf4j
public class SigmaRuleParser {

    private final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());

    public enum Modifier {
        EXACT, CONTAINS, STARTSWITH, ENDSWITH, REGEX
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class FieldCriteria {
        private String fieldName;
        private Modifier modifier;
        private List<String> expectedValues;
        private List<Pattern> compiledPatterns;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SelectionBlock {
        private String name;
        private List<FieldCriteria> criteriaList;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ParsedSigmaRule {
        private String id;
        private String title;
        private String description;
        private String severity;
        private String category;
        private String product;
        private String techniqueId;
        private String tactic;
        private Map<String, SelectionBlock> selections;
        private String condition;
        private String rawYaml;
    }

    public ParsedSigmaRule parse(String yamlText) {
        if (yamlText == null || yamlText.isBlank()) {
            throw new IllegalArgumentException("Sigma YAML text cannot be blank");
        }

        try {
            JsonNode root = yamlMapper.readTree(yamlText);

            String id = root.has("id") ? root.get("id").asText() : "SIGMA-" + UUID.randomUUID().toString().substring(0, 8);
            String title = root.has("title") ? root.get("title").asText() : "Untitled Sigma Rule";
            String description = root.has("description") ? root.get("description").asText() : "";
            String severity = root.has("level") ? root.get("level").asText().toLowerCase() : "medium";

            // Logsource
            String category = null;
            String product = null;
            if (root.has("logsource")) {
                JsonNode ls = root.get("logsource");
                if (ls.has("category")) category = ls.get("category").asText();
                if (ls.has("product")) product = ls.get("product").asText();
            }

            // Tags / MITRE
            String techniqueId = null;
            String tactic = null;
            if (root.has("tags") && root.get("tags").isArray()) {
                for (JsonNode tagNode : root.get("tags")) {
                    String tag = tagNode.asText().toLowerCase();
                    if (tag.startsWith("attack.t") && Character.isDigit(tag.charAt(8))) {
                        techniqueId = tag.replace("attack.", "").toUpperCase();
                    } else if (tag.startsWith("attack.")) {
                        String remainder = tag.substring("attack.".length());
                        if (!remainder.startsWith("t") || !Character.isDigit(remainder.charAt(1))) {
                            tactic = capitalizeWords(remainder.replace("_", " "));
                        }
                    }
                }
            }

            // Detection
            Map<String, SelectionBlock> selections = new HashMap<>();
            String condition = "selection";

            if (root.has("detection")) {
                JsonNode detection = root.get("detection");
                Iterator<Map.Entry<String, JsonNode>> fields = detection.fields();
                while (fields.hasNext()) {
                    Map.Entry<String, JsonNode> entry = fields.next();
                    String key = entry.getKey();
                    if ("condition".equalsIgnoreCase(key)) {
                        condition = entry.getValue().asText().trim();
                    } else {
                        SelectionBlock block = parseSelectionBlock(key, entry.getValue());
                        selections.put(key, block);
                    }
                }
            }

            return ParsedSigmaRule.builder()
                    .id(id)
                    .title(title)
                    .description(description)
                    .severity(severity)
                    .category(category)
                    .product(product)
                    .techniqueId(techniqueId)
                    .tactic(tactic)
                    .selections(selections)
                    .condition(condition)
                    .rawYaml(yamlText)
                    .build();

        } catch (Exception e) {
            log.error("Failed to parse Sigma YAML rule: {}", e.getMessage());
            throw new IllegalArgumentException("Invalid Sigma YAML syntax: " + e.getMessage(), e);
        }
    }

    private SelectionBlock parseSelectionBlock(String blockName, JsonNode node) {
        List<FieldCriteria> criteriaList = new ArrayList<>();

        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> fieldEntry = fields.next();
                String rawField = fieldEntry.getKey();
                JsonNode valNode = fieldEntry.getValue();

                String fieldName = rawField;
                Modifier modifier = Modifier.EXACT;

                if (rawField.contains("|")) {
                    String[] parts = rawField.split("\\|", 2);
                    fieldName = parts[0].trim();
                    String modStr = parts[1].trim().toLowerCase();
                    if (modStr.contains("contains")) modifier = Modifier.CONTAINS;
                    else if (modStr.contains("startswith")) modifier = Modifier.STARTSWITH;
                    else if (modStr.contains("endswith")) modifier = Modifier.ENDSWITH;
                    else if (modStr.contains("re") || modStr.contains("regex")) modifier = Modifier.REGEX;
                }

                List<String> values = new ArrayList<>();
                List<Pattern> patterns = new ArrayList<>();

                if (valNode.isArray()) {
                    for (JsonNode item : valNode) {
                        String v = item.asText();
                        values.add(v);
                        if (modifier == Modifier.REGEX) {
                            try { patterns.add(Pattern.compile(v, Pattern.CASE_INSENSITIVE)); } catch (Exception ignored) {}
                        }
                    }
                } else {
                    String v = valNode.asText();
                    values.add(v);
                    if (modifier == Modifier.REGEX) {
                        try { patterns.add(Pattern.compile(v, Pattern.CASE_INSENSITIVE)); } catch (Exception ignored) {}
                    }
                }

                criteriaList.add(FieldCriteria.builder()
                        .fieldName(fieldName)
                        .modifier(modifier)
                        .expectedValues(values)
                        .compiledPatterns(patterns)
                        .build());
            }
        }

        return SelectionBlock.builder()
                .name(blockName)
                .criteriaList(criteriaList)
                .build();
    }

    private String capitalizeWords(String str) {
        if (str == null || str.isEmpty()) return str;
        String[] words = str.split("\\s+");
        StringBuilder sb = new StringBuilder();
        for (String w : words) {
            if (!w.isEmpty()) {
                sb.append(Character.toUpperCase(w.charAt(0))).append(w.substring(1).toLowerCase()).append(" ");
            }
        }
        return sb.toString().trim();
    }
}
