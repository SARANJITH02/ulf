package com.ulpf.parsers;

import com.ulpf.detection.LogFormat;
import com.ulpf.normalization.OcsfSchema;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
@Slf4j
public class CsvKvParser implements ParserPlugin {

    private boolean active = true;

    private static final Pattern KV_PATTERN = Pattern.compile("([a-zA-Z0-9_.-]+)=([\"']?)([^\"',\\s]+)\\2");

    @Override
    public String getName() {
        return "csv_kv_parser";
    }

    @Override
    public String getDisplayName() {
        return "Palo Alto CSV & Key-Value Log Parser";
    }

    @Override
    public String getVersion() {
        return "1.0.0";
    }

    @Override
    public String getFormatType() {
        return "CSV/KV";
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
        if (detectedFormat == LogFormat.CSV) return true;
        return (rawMessage.contains(",") && rawMessage.split(",").length >= 5) ||
               (rawMessage.contains("=") && rawMessage.contains("src"));
    }

    @Override
    public ParsedLogResult parse(String rawMessage) {
        if (rawMessage == null || rawMessage.isBlank()) {
            return ParsedLogResult.builder().success(false).errorMessage("Empty payload").build();
        }

        try {
            String trimmed = rawMessage.trim();
            // Check if standard comma-separated Palo Alto or similar
            if (trimmed.contains(",") && trimmed.split(",").length >= 10) {
                return parsePaloAltoCsv(trimmed, rawMessage);
            }
            return parseKv(trimmed, rawMessage);
        } catch (Exception e) {
            log.error("Failed parsing CSV/KV log: {}", rawMessage, e);
            return ParsedLogResult.builder()
                    .success(false)
                    .parserName(getName())
                    .parserVersion(getVersion())
                    .formatType(getFormatType())
                    .errorMessage("CSV/KV parser exception: " + e.getMessage())
                    .build();
        }
    }

    private ParsedLogResult parsePaloAltoCsv(String line, String rawMessage) {
        String[] cols = line.split(",", -1);
        Map<String, Double> confidence = new HashMap<>();
        Map<String, Object> extensions = new HashMap<>();

        // Typical PAN-OS CSV field positions
        // 0: future_use, 1: receive_time, 2: serial_num, 3: type, 4: threat/content_type, 5: future_use,
        // 6: generated_time, 7: src_ip, 8: dst_ip, 9: nat_src_ip, 10: nat_dst_ip, 11: rule_name, 12: src_user,
        // ... 24: src_port, 25: dst_port, 29: proto, 30: action, 31: bytes, 32: bytes_sent, 33: bytes_recv
        String logType = cols.length > 3 ? cols[3] : "TRAFFIC";
        String srcIp = cols.length > 7 ? cols[7] : null;
        String dstIp = cols.length > 8 ? cols[8] : null;
        String ruleName = cols.length > 11 ? cols[11] : null;
        String user = cols.length > 12 && !cols[12].isBlank() ? cols[12] : null;
        String app = cols.length > 14 ? cols[14] : null;
        Integer srcPort = cols.length > 24 ? parsePort(cols[24]) : null;
        Integer dstPort = cols.length > 25 ? parsePort(cols[25]) : null;
        String proto = cols.length > 29 && !cols[29].isBlank() ? cols[29].toUpperCase() : "TCP";
        String rawAction = cols.length > 30 ? cols[30] : "allow";

        for (int i = 0; i < cols.length; i++) {
            extensions.put("field_" + i, cols[i]);
        }
        if (ruleName != null) extensions.put("ruleName", ruleName);
        if (app != null) extensions.put("application", app);

        if (srcIp != null && !srcIp.isBlank()) confidence.put("source.ip", 0.98);
        if (dstIp != null && !dstIp.isBlank()) confidence.put("destination.ip", 0.98);
        if (srcPort != null) confidence.put("source.port", 0.98);
        if (dstPort != null) confidence.put("destination.port", 0.98);
        confidence.put("network.protocol", 0.98);
        confidence.put("event.action", 0.95);
        confidence.put("observer.vendor", 0.99);

        String action = normalizeAction(rawAction);

        OcsfSchema ocsf = OcsfSchema.builder()
                .timestampUtc(Instant.now().toString())
                .event(OcsfSchema.EventDetail.builder()
                        .category("network_traffic")
                        .type("firewall")
                        .action(action)
                        .severity(action.equalsIgnoreCase("blocked") ? "high" : "informational")
                        .severityId(action.equalsIgnoreCase("blocked") ? 4 : 1)
                        .message("Palo Alto PAN-OS " + logType + " Event: " + action + " " + proto)
                        .build())
                .source(OcsfSchema.Endpoint.builder()
                        .ip(srcIp)
                        .port(srcPort)
                        .user(user)
                        .build())
                .destination(OcsfSchema.Endpoint.builder()
                        .ip(dstIp)
                        .port(dstPort)
                        .build())
                .network(OcsfSchema.NetworkDetail.builder()
                        .protocol(proto)
                        .direction("egress")
                        .build())
                .observer(OcsfSchema.ObserverDetail.builder()
                        .vendor("Palo Alto Networks")
                        .product("PAN-OS")
                        .build())
                .raw(OcsfSchema.RawDetail.builder()
                        .message(rawMessage)
                        .format("CSV")
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
                .formatType("CSV")
                .fieldConfidence(confidence)
                .build();
    }

    private ParsedLogResult parseKv(String line, String rawMessage) {
        Map<String, String> kv = new HashMap<>();
        Matcher m = KV_PATTERN.matcher(line);
        while (m.find()) {
            kv.put(m.group(1).toLowerCase(), m.group(3));
        }

        Map<String, Double> confidence = new HashMap<>();
        Map<String, Object> extensions = new HashMap<>(kv);

        String srcIp = kv.getOrDefault("src", kv.getOrDefault("src_ip", kv.getOrDefault("source_ip", null)));
        String dstIp = kv.getOrDefault("dst", kv.getOrDefault("dst_ip", kv.getOrDefault("dest_ip", null)));
        Integer srcPort = parsePort(kv.getOrDefault("spt", kv.getOrDefault("src_port", kv.getOrDefault("source_port", null))));
        Integer dstPort = parsePort(kv.getOrDefault("dpt", kv.getOrDefault("dst_port", kv.getOrDefault("dest_port", null))));
        String proto = kv.getOrDefault("proto", kv.getOrDefault("protocol", "TCP")).toUpperCase();
        String action = normalizeAction(kv.getOrDefault("action", kv.getOrDefault("act", kv.getOrDefault("status", "allowed"))));
        String user = kv.getOrDefault("user", kv.getOrDefault("usr", kv.getOrDefault("username", null)));
        String device = kv.getOrDefault("device", kv.getOrDefault("vendor", "Generic-KV"));

        if (srcIp != null) confidence.put("source.ip", 0.95);
        if (dstIp != null) confidence.put("destination.ip", 0.95);
        if (srcPort != null) confidence.put("source.port", 0.95);
        if (dstPort != null) confidence.put("destination.port", 0.95);
        confidence.put("event.action", 0.90);

        OcsfSchema ocsf = OcsfSchema.builder()
                .timestampUtc(Instant.now().toString())
                .event(OcsfSchema.EventDetail.builder()
                        .category("network_traffic")
                        .type("kv_log")
                        .action(action)
                        .severity(action.equalsIgnoreCase("blocked") ? "medium" : "informational")
                        .severityId(action.equalsIgnoreCase("blocked") ? 3 : 1)
                        .message("KV Event: " + action + " " + proto)
                        .build())
                .source(OcsfSchema.Endpoint.builder().ip(srcIp).port(srcPort).user(user).build())
                .destination(OcsfSchema.Endpoint.builder().ip(dstIp).port(dstPort).build())
                .network(OcsfSchema.NetworkDetail.builder().protocol(proto).build())
                .observer(OcsfSchema.ObserverDetail.builder().vendor(device).product("KV-Parser").build())
                .raw(OcsfSchema.RawDetail.builder().message(rawMessage).format("KV").build())
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
                .formatType("KV")
                .fieldConfidence(confidence)
                .build();
    }

    private Integer parsePort(String s) {
        if (s == null) return null;
        try {
            int p = Integer.parseInt(s.trim());
            return (p >= 0 && p <= 65535) ? p : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private String normalizeAction(String act) {
        if (act == null) return "informational";
        String lower = act.toLowerCase();
        if (lower.contains("deny") || lower.contains("denied") || lower.contains("block") || lower.contains("drop") || lower.contains("reject")) {
            return "blocked";
        }
        if (lower.contains("allow") || lower.contains("permit") || lower.contains("accept") || lower.contains("pass")) {
            return "allowed";
        }
        return lower;
    }
}
