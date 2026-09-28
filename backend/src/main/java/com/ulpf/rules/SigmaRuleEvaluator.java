package com.ulpf.rules;

import com.ulpf.normalization.OcsfSchema;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Pattern;

@Component
@RequiredArgsConstructor
@Slf4j
public class SigmaRuleEvaluator {

    /**
     * Evaluate a parsed Sigma rule against a normalized OCSF event.
     */
    public Optional<OcsfSchema.SigmaMatchSummary> evaluateRule(SigmaRuleParser.ParsedSigmaRule rule, OcsfSchema ocsf) {
        if (rule == null || ocsf == null) {
            return Optional.empty();
        }

        Map<String, String> eventFields = extractEventFields(ocsf);

        // Optional logsource product/category check
        if (rule.getCategory() != null && !rule.getCategory().isBlank()) {
            String eventCat = eventFields.getOrDefault("event.category", "");
            String eventType = eventFields.getOrDefault("event.type", "");
            if (!eventCat.equalsIgnoreCase(rule.getCategory()) && !eventType.equalsIgnoreCase(rule.getCategory()) && !rule.getCategory().equalsIgnoreCase("network_traffic")) {
                // allow fallback for network perimeter logs
            }
        }

        // Evaluate all selection blocks
        Map<String, Boolean> selectionResults = new HashMap<>();
        for (Map.Entry<String, SigmaRuleParser.SelectionBlock> entry : rule.getSelections().entrySet()) {
            boolean blockMatched = evaluateSelectionBlock(entry.getValue(), eventFields, ocsf);
            selectionResults.put(entry.getKey(), blockMatched);
        }

        // Evaluate condition expression
        boolean finalMatch = evaluateCondition(rule.getCondition(), selectionResults);

        if (finalMatch) {
            return Optional.of(OcsfSchema.SigmaMatchSummary.builder()
                    .ruleId(rule.getId())
                    .ruleTitle(rule.getTitle())
                    .severity(rule.getSeverity())
                    .techniqueId(rule.getTechniqueId())
                    .tactic(rule.getTactic())
                    .matchedDetails("Sigma rule matched: " + rule.getTitle() + " (" + rule.getCondition() + ")")
                    .build());
        }

        return Optional.empty();
    }

    private boolean evaluateSelectionBlock(SigmaRuleParser.SelectionBlock block, Map<String, String> eventFields, OcsfSchema ocsf) {
        if (block == null || block.getCriteriaList().isEmpty()) {
            return false;
        }

        // In Sigma, all criteria within a single selection block must match (AND)
        for (SigmaRuleParser.FieldCriteria criteria : block.getCriteriaList()) {
            if (!evaluateCriteria(criteria, eventFields, ocsf)) {
                return false;
            }
        }
        return true;
    }

    private boolean evaluateCriteria(SigmaRuleParser.FieldCriteria criteria, Map<String, String> eventFields, OcsfSchema ocsf) {
        String targetField = criteria.getFieldName().toLowerCase();
        String actualValue = resolveFieldValue(targetField, eventFields);

        if (actualValue == null || actualValue.isBlank()) {
            // Fallback: If searching for general keywords and field name is 'keywords' or 'message'
            if (targetField.equals("message") || targetField.equals("raw") || targetField.equals("keywords") || targetField.equals("payload")) {
                actualValue = eventFields.getOrDefault("raw.message", "");
            } else {
                return false;
            }
        }

        String actualLower = actualValue.toLowerCase();

        // In Sigma, a list of values in a criteria is evaluated as OR (any matches)
        for (int i = 0; i < criteria.getExpectedValues().size(); i++) {
            String expected = criteria.getExpectedValues().get(i);
            String expectedLower = expected.toLowerCase();

            switch (criteria.getModifier()) {
                case EXACT:
                    if (actualLower.equals(expectedLower)) return true;
                    break;
                case CONTAINS:
                    if (actualLower.contains(expectedLower)) return true;
                    break;
                case STARTSWITH:
                    if (actualLower.startsWith(expectedLower)) return true;
                    break;
                case ENDSWITH:
                    if (actualLower.endsWith(expectedLower)) return true;
                    break;
                case REGEX:
                    if (i < criteria.getCompiledPatterns().size()) {
                        Pattern p = criteria.getCompiledPatterns().get(i);
                        if (p != null && p.matcher(actualValue).find()) return true;
                    } else {
                        try {
                            if (Pattern.compile(expected, Pattern.CASE_INSENSITIVE).matcher(actualValue).find()) return true;
                        } catch (Exception ignored) {}
                    }
                    break;
            }
        }

        return false;
    }

    private String resolveFieldValue(String fieldName, Map<String, String> eventFields) {
        String direct = eventFields.get(fieldName);
        if (direct != null) return direct;

        // Aliases resolution
        return switch (fieldName) {
            case "dst_port", "dpt", "port", "destination_port" -> eventFields.get("destination.port");
            case "src_port", "spt", "source_port" -> eventFields.get("source.port");
            case "dst_ip", "dst", "destination_ip" -> eventFields.get("destination.ip");
            case "src_ip", "src", "source_ip" -> eventFields.get("source.ip");
            case "action", "act", "status" -> eventFields.get("event.action");
            case "proto", "protocol", "transport" -> eventFields.get("network.protocol");
            case "category" -> eventFields.get("event.category");
            case "type" -> eventFields.get("event.type");
            case "msg", "message", "raw", "original" -> eventFields.get("raw.message");
            case "vendor" -> eventFields.get("observer.vendor");
            case "product" -> eventFields.get("observer.product");
            case "user", "username", "suser" -> eventFields.get("source.user");
            default -> null;
        };
    }

    private boolean evaluateCondition(String condition, Map<String, Boolean> selectionResults) {
        if (condition == null || condition.isBlank()) {
            return selectionResults.values().stream().anyMatch(Boolean::booleanValue);
        }

        String cond = condition.trim().toLowerCase();

        // 1. "1 of selection*" or "1 of them"
        if (cond.startsWith("1 of selection") || cond.startsWith("1 of them") || cond.contains("any of selection")) {
            return selectionResults.values().stream().anyMatch(Boolean::booleanValue);
        }

        // 2. "all of selection*" or "all of them"
        if (cond.startsWith("all of selection") || cond.startsWith("all of them")) {
            return !selectionResults.isEmpty() && selectionResults.values().stream().allMatch(Boolean::booleanValue);
        }

        // 3. "selection and not filter"
        if (cond.contains(" and not ")) {
            String[] parts = cond.split(" and not ");
            if (parts.length == 2) {
                boolean left = evaluateSimpleToken(parts[0].trim(), selectionResults);
                boolean right = evaluateSimpleToken(parts[1].trim(), selectionResults);
                return left && !right;
            }
        }

        // 4. "selection1 and selection2"
        if (cond.contains(" and ")) {
            String[] parts = cond.split(" and ");
            for (String p : parts) {
                if (!evaluateSimpleToken(p.trim(), selectionResults)) return false;
            }
            return true;
        }

        // 5. "selection1 or selection2"
        if (cond.contains(" or ")) {
            String[] parts = cond.split(" or ");
            for (String p : parts) {
                if (evaluateSimpleToken(p.trim(), selectionResults)) return true;
            }
            return false;
        }

        // 6. "not selection"
        if (cond.startsWith("not ")) {
            String token = cond.substring(4).trim();
            return !evaluateSimpleToken(token, selectionResults);
        }

        // Single block name e.g. "selection"
        return evaluateSimpleToken(cond, selectionResults);
    }

    private boolean evaluateSimpleToken(String token, Map<String, Boolean> results) {
        String clean = token.replace("(", "").replace(")", "").trim();
        return results.getOrDefault(clean, false);
    }

    private Map<String, String> extractEventFields(OcsfSchema ocsf) {
        Map<String, String> map = new HashMap<>();

        if (ocsf.getEvent() != null) {
            if (ocsf.getEvent().getCategory() != null) map.put("event.category", ocsf.getEvent().getCategory());
            if (ocsf.getEvent().getType() != null) map.put("event.type", ocsf.getEvent().getType());
            if (ocsf.getEvent().getAction() != null) map.put("event.action", ocsf.getEvent().getAction());
            if (ocsf.getEvent().getSeverity() != null) map.put("event.severity", ocsf.getEvent().getSeverity());
            if (ocsf.getEvent().getMessage() != null) map.put("event.message", ocsf.getEvent().getMessage());
        }

        if (ocsf.getSource() != null) {
            if (ocsf.getSource().getIp() != null) map.put("source.ip", ocsf.getSource().getIp());
            if (ocsf.getSource().getPort() != null) map.put("source.port", String.valueOf(ocsf.getSource().getPort()));
            if (ocsf.getSource().getUser() != null) map.put("source.user", ocsf.getSource().getUser());
            if (ocsf.getSource().getHostname() != null) map.put("source.hostname", ocsf.getSource().getHostname());
        }

        if (ocsf.getDestination() != null) {
            if (ocsf.getDestination().getIp() != null) map.put("destination.ip", ocsf.getDestination().getIp());
            if (ocsf.getDestination().getPort() != null) map.put("destination.port", String.valueOf(ocsf.getDestination().getPort()));
            if (ocsf.getDestination().getHostname() != null) map.put("destination.hostname", ocsf.getDestination().getHostname());
        }

        if (ocsf.getNetwork() != null) {
            if (ocsf.getNetwork().getProtocol() != null) map.put("network.protocol", ocsf.getNetwork().getProtocol());
            if (ocsf.getNetwork().getDirection() != null) map.put("network.direction", ocsf.getNetwork().getDirection());
            if (ocsf.getNetwork().getTransport() != null) map.put("network.transport", ocsf.getNetwork().getTransport());
        }

        if (ocsf.getObserver() != null) {
            if (ocsf.getObserver().getVendor() != null) map.put("observer.vendor", ocsf.getObserver().getVendor());
            if (ocsf.getObserver().getProduct() != null) map.put("observer.product", ocsf.getObserver().getProduct());
        }

        if (ocsf.getRaw() != null && ocsf.getRaw().getMessage() != null) {
            map.put("raw.message", ocsf.getRaw().getMessage());
        }

        // Extensions
        if (ocsf.getExtensions() != null) {
            for (Map.Entry<String, Object> ext : ocsf.getExtensions().entrySet()) {
                if (ext.getValue() != null) {
                    map.put("extensions." + ext.getKey(), ext.getValue().toString());
                    map.put(ext.getKey(), ext.getValue().toString());
                }
            }
        }

        return map;
    }
}
