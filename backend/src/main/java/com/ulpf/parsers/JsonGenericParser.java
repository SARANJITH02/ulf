package com.ulpf.parsers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ulpf.detection.LogFormat;
import com.ulpf.normalization.OcsfSchema;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.*;

@Component
@Slf4j
public class JsonGenericParser implements ParserPlugin {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private boolean active = true;

    @Override
    public String getName() {
        return "json_generic_parser";
    }

    @Override
    public String getDisplayName() {
        return "JSON & CloudTrail / Suricata EVE Parser";
    }

    @Override
    public String getVersion() {
        return "1.0.0";
    }

    @Override
    public String getFormatType() {
        return "JSON";
    }

    @Override
    public boolean isActive() {
        return active;
    }

    @Override
    public void setActive(boolean active) {
        this.active = active;
    }

    @Override
    public boolean canParse(String rawMessage, LogFormat detectedFormat) {
        if (!active || rawMessage == null) return false;
        if (detectedFormat == LogFormat.JSON) return true;
        String trimmed = rawMessage.trim();
        return (trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"));
    }

    @Override
    public ParsedLogResult parse(String rawMessage) {
        if (rawMessage == null || rawMessage.isBlank()) {
            return ParsedLogResult.builder().success(false).errorMessage("Empty JSON payload").build();
        }

        try {
            JsonNode root = objectMapper.readTree(rawMessage.trim());
            if (root.isArray() && !root.isEmpty()) {
                root = root.get(0);
            }

            Map<String, Double> confidence = new HashMap<>();
            Map<String, Object> extensions = new HashMap<>();

            // 1. Check if AWS CloudTrail
            if (root.has("eventSource") || root.has("awsRegion") || root.has("userIdentity")) {
                return parseCloudTrail(root, rawMessage);
            }

            // 2. Check if Suricata EVE JSON
            if (root.has("event_type") || root.has("flow_id") || (root.has("src_ip") && root.has("dest_ip"))) {
                return parseSuricataEve(root, rawMessage);
            }

            // 3. Generic JSON mapping
            return parseGenericJson(root, rawMessage);

        } catch (Exception e) {
            log.error("Failed parsing JSON log: {}", rawMessage, e);
            return ParsedLogResult.builder()
                    .success(false)
                    .parserName(getName())
                    .parserVersion(getVersion())
                    .formatType(getFormatType())
                    .errorMessage("JSON parse error: " + e.getMessage())
                    .build();
        }
    }

    private ParsedLogResult parseCloudTrail(JsonNode root, String rawMessage) {
        Map<String, Double> confidence = new HashMap<>();
        Map<String, Object> extensions = new HashMap<>();

        String timestamp = root.path("eventTime").asText(Instant.now().toString());
        String eventSource = root.path("eventSource").asText("aws.cloudtrail");
        String eventName = root.path("eventName").asText("API-Call");
        String srcIp = root.path("sourceIPAddress").asText(null);
        String userAgent = root.path("userAgent").asText(null);
        String region = root.path("awsRegion").asText(null);
        String errorCode = root.path("errorCode").asText(null);

        String username = null;
        if (root.has("userIdentity")) {
            JsonNode userNode = root.get("userIdentity");
            username = userNode.path("userName").asText(userNode.path("principalId").asText(null));
        }

        String action = (errorCode != null && !errorCode.isBlank()) ? "blocked" : "allowed";
        String severity = (errorCode != null && !errorCode.isBlank()) ? "medium" : "informational";
        int severityId = (errorCode != null && !errorCode.isBlank()) ? 3 : 1;

        if (srcIp != null) confidence.put("source.ip", 0.98);
        if (username != null) confidence.put("source.user", 0.95);
        confidence.put("event.action", 0.95);
        confidence.put("observer.vendor", 0.99);

        // Put entire json fields into extensions for lossless preservation
        Iterator<Map.Entry<String, JsonNode>> fields = root.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            extensions.put(entry.getKey(), entry.getValue().isTextual() ? entry.getValue().asText() : entry.getValue().toString());
        }

        OcsfSchema ocsf = OcsfSchema.builder()
                .timestampUtc(timestamp)
                .event(OcsfSchema.EventDetail.builder()
                        .category("system_activity")
                        .type("cloud_audit")
                        .action(action)
                        .severity(severity)
                        .severityId(severityId)
                        .message("AWS " + eventSource + " - " + eventName)
                        .build())
                .source(OcsfSchema.Endpoint.builder()
                        .ip(srcIp)
                        .user(username)
                        .build())
                .destination(OcsfSchema.Endpoint.builder()
                        .hostname(eventSource)
                        .build())
                .observer(OcsfSchema.ObserverDetail.builder()
                        .vendor("AWS")
                        .product("CloudTrail")
                        .version(region)
                        .build())
                .raw(OcsfSchema.RawDetail.builder()
                        .message(rawMessage)
                        .format("JSON")
                        .build())
                .extensions(extensions)
                .ulpf(OcsfSchema.UlpfMetadata.builder()
                        .parserName(getName())
                        .parserVersion(getVersion())
                        .mappingConfidence(confidence)
                        .build())
                .build();

        return ParsedLogResult.builder()
                .success(true)
                .normalizedEvent(ocsf)
                .parserName(getName())
                .parserVersion(getVersion())
                .formatType("JSON")
                .fieldConfidence(confidence)
                .build();
    }

    private ParsedLogResult parseSuricataEve(JsonNode root, String rawMessage) {
        Map<String, Double> confidence = new HashMap<>();
        Map<String, Object> extensions = new HashMap<>();

        String timestamp = root.path("timestamp").asText(Instant.now().toString());
        String eventType = root.path("event_type").asText("alert");
        String srcIp = root.path("src_ip").asText(null);
        int srcPort = root.path("src_port").asInt(0);
        String destIp = root.path("dest_ip").asText(null);
        int destPort = root.path("dest_port").asInt(0);
        String proto = root.path("proto").asText("TCP").toUpperCase();

        String alertMsg = "Suricata Event: " + eventType;
        String action = "allowed";
        String severity = "informational";
        int severityId = 1;

        if (root.has("alert")) {
            JsonNode alertNode = root.get("alert");
            alertMsg = alertNode.path("signature").asText(alertMsg);
            String rawAction = alertNode.path("action").asText("allowed");
            action = rawAction.equalsIgnoreCase("blocked") || rawAction.equalsIgnoreCase("drop") ? "blocked" : "allowed";
            int sev = alertNode.path("severity").asInt(3);
            severityId = sev == 1 ? 5 : (sev == 2 ? 4 : 3);
            severity = severityId >= 4 ? "high" : "medium";
        }

        if (srcIp != null) confidence.put("source.ip", 0.99);
        if (destIp != null) confidence.put("destination.ip", 0.99);
        if (srcPort > 0) confidence.put("source.port", 0.99);
        if (destPort > 0) confidence.put("destination.port", 0.99);
        confidence.put("network.protocol", 0.99);
        confidence.put("event.action", 0.96);

        Iterator<Map.Entry<String, JsonNode>> fields = root.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            extensions.put(entry.getKey(), entry.getValue().isTextual() ? entry.getValue().asText() : entry.getValue().toString());
        }

        OcsfSchema ocsf = OcsfSchema.builder()
                .timestampUtc(timestamp)
                .event(OcsfSchema.EventDetail.builder()
                        .category("network_traffic")
                        .type("ids")
                        .action(action)
                        .severity(severity)
                        .severityId(severityId)
                        .message(alertMsg)
                        .build())
                .source(OcsfSchema.Endpoint.builder()
                        .ip(srcIp)
                        .port(srcPort > 0 ? srcPort : null)
                        .build())
                .destination(OcsfSchema.Endpoint.builder()
                        .ip(destIp)
                        .port(destPort > 0 ? destPort : null)
                        .build())
                .network(OcsfSchema.NetworkDetail.builder()
                        .protocol(proto)
                        .build())
                .observer(OcsfSchema.ObserverDetail.builder()
                        .vendor("Suricata")
                        .product("EVE")
                        .build())
                .raw(OcsfSchema.RawDetail.builder()
                        .message(rawMessage)
                        .format("JSON")
                        .build())
                .extensions(extensions)
                .ulpf(OcsfSchema.UlpfMetadata.builder()
                        .parserName(getName())
                        .parserVersion(getVersion())
                        .mappingConfidence(confidence)
                        .build())
                .build();

        return ParsedLogResult.builder()
                .success(true)
                .normalizedEvent(ocsf)
                .parserName(getName())
                .parserVersion(getVersion())
                .formatType("JSON")
                .fieldConfidence(confidence)
                .build();
    }

    private ParsedLogResult parseGenericJson(JsonNode root, String rawMessage) {
        Map<String, Double> confidence = new HashMap<>();
        Map<String, Object> extensions = new HashMap<>();

        String srcIp = findFirstString(root, "src_ip", "source_ip", "src", "client_ip", "sourceAddress");
        String dstIp = findFirstString(root, "dst_ip", "dest_ip", "destination_ip", "dst", "server_ip", "destinationAddress");
        Integer srcPort = findFirstInt(root, "src_port", "source_port", "spt");
        Integer dstPort = findFirstInt(root, "dst_port", "dest_port", "destination_port", "dpt");
        String proto = findFirstString(root, "protocol", "proto", "transport");
        String action = findFirstString(root, "action", "act", "status", "decision");
        String user = findFirstString(root, "user", "username", "account", "src_user");
        String msg = findFirstString(root, "message", "msg", "log", "description");
        String timestamp = findFirstString(root, "timestamp", "time", "@timestamp", "date");

        if (srcIp != null) confidence.put("source.ip", 0.90);
        if (dstIp != null) confidence.put("destination.ip", 0.90);
        if (srcPort != null) confidence.put("source.port", 0.90);
        if (dstPort != null) confidence.put("destination.port", 0.90);
        if (action != null) confidence.put("event.action", 0.85);

        Iterator<Map.Entry<String, JsonNode>> fields = root.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            extensions.put(entry.getKey(), entry.getValue().isTextual() ? entry.getValue().asText() : entry.getValue().toString());
        }

        String normAction = action != null ? action.toLowerCase() : "informational";
        if (normAction.contains("deny") || normAction.contains("block") || normAction.contains("drop")) normAction = "blocked";
        else if (normAction.contains("allow") || normAction.contains("accept") || normAction.contains("pass")) normAction = "allowed";

        OcsfSchema ocsf = OcsfSchema.builder()
                .timestampUtc(timestamp != null ? timestamp : Instant.now().toString())
                .event(OcsfSchema.EventDetail.builder()
                        .category("network_traffic")
                        .type("generic_json")
                        .action(normAction)
                        .severity(normAction.equals("blocked") ? "medium" : "informational")
                        .severityId(normAction.equals("blocked") ? 3 : 1)
                        .message(msg != null ? msg : "JSON Security Log")
                        .build())
                .source(OcsfSchema.Endpoint.builder().ip(srcIp).port(srcPort).user(user).build())
                .destination(OcsfSchema.Endpoint.builder().ip(dstIp).port(dstPort).build())
                .network(OcsfSchema.NetworkDetail.builder().protocol(proto != null ? proto.toUpperCase() : "TCP").build())
                .observer(OcsfSchema.ObserverDetail.builder().vendor("Generic").product("JSON").build())
                .raw(OcsfSchema.RawDetail.builder().message(rawMessage).format("JSON").build())
                .extensions(extensions)
                .ulpf(OcsfSchema.UlpfMetadata.builder()
                        .parserName(getName())
                        .parserVersion(getVersion())
                        .mappingConfidence(confidence)
                        .build())
                .build();

        return ParsedLogResult.builder()
                .success(true)
                .normalizedEvent(ocsf)
                .parserName(getName())
                .parserVersion(getVersion())
                .formatType("JSON")
                .fieldConfidence(confidence)
                .build();
    }

    private String findFirstString(JsonNode node, String... keys) {
        for (String k : keys) {
            if (node.has(k) && !node.get(k).isNull()) {
                return node.get(k).asText();
            }
        }
        return null;
    }

    private Integer findFirstInt(JsonNode node, String... keys) {
        for (String k : keys) {
            if (node.has(k) && node.get(k).isInt()) {
                return node.get(k).asInt();
            } else if (node.has(k) && node.get(k).isTextual()) {
                try {
                    return Integer.parseInt(node.get(k).asText());
                } catch (NumberFormatException ignored) {}
            }
        }
        return null;
    }
}
