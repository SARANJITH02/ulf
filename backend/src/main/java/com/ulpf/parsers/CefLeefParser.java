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
public class CefLeefParser implements ParserPlugin {

    private boolean active = true;

    // Matches CEF header: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
    private static final Pattern CEF_HEADER_PATTERN = Pattern.compile(
            ".*?CEF:\\s*(\\d+)\\|([^|]*)\\|([^|]*)\\|([^|]*)\\|([^|]*)\\|([^|]*)\\|([^|]*)\\|(.*)",
            Pattern.DOTALL
    );

    // Matches LEEF 1.0/2.0 header: LEEF:Version|Vendor|Product|Version|EventID|[Delimiter]|Extension
    private static final Pattern LEEF_HEADER_PATTERN = Pattern.compile(
            ".*?LEEF:\\s*([12]\\.\\d+)\\|([^|]*)\\|([^|]*)\\|([^|]*)\\|([^|]*)\\|(.*)",
            Pattern.DOTALL
    );

    private static final Pattern KV_PATTERN = Pattern.compile("([a-zA-Z0-9_.-]+)=((?:\\\\=|[^= ])*)");

    @Override
    public String getName() {
        return "cef_leef_parser";
    }

    @Override
    public String getDisplayName() {
        return "ArcSight CEF & IBM LEEF Parser";
    }

    @Override
    public String getVersion() {
        return "1.0.0";
    }

    @Override
    public String getFormatType() {
        return "CEF/LEEF";
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
        return detectedFormat == LogFormat.CEF || detectedFormat == LogFormat.LEEF ||
                rawMessage.contains("CEF:") || rawMessage.contains("LEEF:");
    }

    @Override
    public ParsedLogResult parse(String rawMessage) {
        if (rawMessage == null || rawMessage.isBlank()) {
            return ParsedLogResult.builder().success(false).errorMessage("Empty payload").build();
        }

        try {
            if (rawMessage.contains("CEF:")) {
                return parseCef(rawMessage);
            } else if (rawMessage.contains("LEEF:")) {
                return parseLeef(rawMessage);
            }
            return ParsedLogResult.builder().success(false).errorMessage("Neither CEF nor LEEF header found").build();
        } catch (Exception e) {
            log.error("Failed parsing CEF/LEEF log: {}", rawMessage, e);
            return ParsedLogResult.builder()
                    .success(false)
                    .parserName(getName())
                    .parserVersion(getVersion())
                    .formatType(getFormatType())
                    .errorMessage("CEF/LEEF parsing exception: " + e.getMessage())
                    .build();
        }
    }

    private ParsedLogResult parseCef(String rawMessage) {
        Matcher m = CEF_HEADER_PATTERN.matcher(rawMessage.trim());
        if (!m.matches()) {
            return ParsedLogResult.builder().success(false).errorMessage("Malformed CEF header").build();
        }

        String cefVersion = m.group(1);
        String vendor = m.group(2).trim();
        String product = m.group(3).trim();
        String version = m.group(4).trim();
        String classId = m.group(5).trim();
        String name = m.group(6).trim();
        String severityStr = m.group(7).trim();
        String extensionStr = m.group(8).trim();

        Map<String, String> ext = parseExtension(extensionStr, ' ');
        Map<String, Double> confidence = new HashMap<>();
        Map<String, Object> extensionsMap = new HashMap<>(ext);
        extensionsMap.put("deviceEventClassId", classId);
        extensionsMap.put("cefVersion", cefVersion);

        String srcIp = ext.getOrDefault("src", ext.getOrDefault("sourceAddress", null));
        String dstIp = ext.getOrDefault("dst", ext.getOrDefault("destinationAddress", null));
        Integer srcPort = parsePort(ext.getOrDefault("spt", ext.getOrDefault("sourcePort", null)));
        Integer dstPort = parsePort(ext.getOrDefault("dpt", ext.getOrDefault("destinationPort", null)));
        String proto = ext.getOrDefault("proto", ext.getOrDefault("app", "TCP")).toUpperCase();
        String act = ext.getOrDefault("act", ext.getOrDefault("action", "informational"));
        String user = ext.getOrDefault("suser", ext.getOrDefault("duser", ext.getOrDefault("srcUser", null)));
        String host = ext.getOrDefault("shost", ext.getOrDefault("dhost", null));

        if (srcIp != null) confidence.put("source.ip", 0.99);
        if (dstIp != null) confidence.put("destination.ip", 0.99);
        if (srcPort != null) confidence.put("source.port", 0.99);
        if (dstPort != null) confidence.put("destination.port", 0.99);
        confidence.put("network.protocol", 0.98);
        confidence.put("event.action", 0.97);
        confidence.put("observer.vendor", 0.99);
        confidence.put("observer.product", 0.99);

        int sevId = parseSeverityId(severityStr);
        String severity = mapSeverityIdToLabel(sevId);
        String normalizedAction = normalizeAction(act);

        OcsfSchema ocsf = OcsfSchema.builder()
                .timestampUtc(ext.containsKey("rt") ? parseCefTimestamp(ext.get("rt")) : Instant.now().toString())
                .event(OcsfSchema.EventDetail.builder()
                        .category("network_traffic")
                        .type("ids")
                        .action(normalizedAction)
                        .severity(severity)
                        .severityId(sevId)
                        .message(name)
                        .build())
                .source(OcsfSchema.Endpoint.builder()
                        .ip(srcIp)
                        .port(srcPort)
                        .hostname(host)
                        .user(user)
                        .build())
                .destination(OcsfSchema.Endpoint.builder()
                        .ip(dstIp)
                        .port(dstPort)
                        .build())
                .network(OcsfSchema.NetworkDetail.builder()
                        .protocol(proto)
                        .direction("ingress")
                        .build())
                .observer(OcsfSchema.ObserverDetail.builder()
                        .vendor(vendor.isEmpty() ? "ArcSight" : vendor)
                        .product(product.isEmpty() ? "CEF" : product)
                        .version(version)
                        .build())
                .raw(OcsfSchema.RawDetail.builder()
                        .message(rawMessage)
                        .format("CEF")
                        .build())
                .extensions(extensionsMap)
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
                .formatType("CEF")
                .fieldConfidence(confidence)
                .build();
    }

    private ParsedLogResult parseLeef(String rawMessage) {
        Matcher m = LEEF_HEADER_PATTERN.matcher(rawMessage.trim());
        if (!m.matches()) {
            return ParsedLogResult.builder().success(false).errorMessage("Malformed LEEF header").build();
        }

        String leefVersion = m.group(1);
        String vendor = m.group(2).trim();
        String product = m.group(3).trim();
        String version = m.group(4).trim();
        String eventId = m.group(5).trim();
        String extensionStr = m.group(6).trim();

        // LEEF extensions typically use tab '\t' delimiter
        char delimiter = extensionStr.contains("\t") ? '\t' : '^';
        Map<String, String> ext = parseExtension(extensionStr, delimiter);

        Map<String, Double> confidence = new HashMap<>();
        Map<String, Object> extensionsMap = new HashMap<>(ext);
        extensionsMap.put("leefVersion", leefVersion);
        extensionsMap.put("eventId", eventId);

        String srcIp = ext.getOrDefault("src", ext.getOrDefault("srcIP", null));
        String dstIp = ext.getOrDefault("dst", ext.getOrDefault("dstIP", null));
        Integer srcPort = parsePort(ext.getOrDefault("srcPort", ext.getOrDefault("spt", null)));
        Integer dstPort = parsePort(ext.getOrDefault("dstPort", ext.getOrDefault("dpt", null)));
        String proto = ext.getOrDefault("proto", "TCP").toUpperCase();
        String user = ext.getOrDefault("usrName", ext.getOrDefault("accountName", null));

        if (srcIp != null) confidence.put("source.ip", 0.99);
        if (dstIp != null) confidence.put("destination.ip", 0.99);
        if (srcPort != null) confidence.put("source.port", 0.99);
        if (dstPort != null) confidence.put("destination.port", 0.99);
        confidence.put("observer.vendor", 0.99);
        confidence.put("observer.product", 0.99);

        OcsfSchema ocsf = OcsfSchema.builder()
                .timestampUtc(Instant.now().toString())
                .event(OcsfSchema.EventDetail.builder()
                        .category("network_traffic")
                        .type("security_event")
                        .action("allowed")
                        .severity("medium")
                        .severityId(3)
                        .message("LEEF Event: " + eventId)
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
                        .build())
                .observer(OcsfSchema.ObserverDetail.builder()
                        .vendor(vendor)
                        .product(product)
                        .version(version)
                        .build())
                .raw(OcsfSchema.RawDetail.builder()
                        .message(rawMessage)
                        .format("LEEF")
                        .build())
                .extensions(extensionsMap)
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
                .formatType("LEEF")
                .fieldConfidence(confidence)
                .build();
    }

    private Map<String, String> parseExtension(String ext, char defaultDelim) {
        Map<String, String> map = new HashMap<>();
        if (ext == null || ext.isBlank()) return map;

        if (defaultDelim == '\t' || defaultDelim == '^') {
            String[] tokens = ext.split(Pattern.quote(String.valueOf(defaultDelim)));
            for (String t : tokens) {
                int eq = t.indexOf('=');
                if (eq > 0) {
                    map.put(t.substring(0, eq).trim(), t.substring(eq + 1).trim());
                }
            }
            return map;
        }

        // Parse key=value pairs separated by spaces, respecting escaped spaces or quotes
        Matcher m = KV_PATTERN.matcher(ext);
        while (m.find()) {
            String k = m.group(1).trim();
            String v = m.group(2).replace("\\=", "=").trim();
            map.put(k, v);
        }
        return map;
    }

    private Integer parsePort(String s) {
        if (s == null) return null;
        try {
            int p = Integer.parseInt(s);
            return (p >= 0 && p <= 65535) ? p : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private int parseSeverityId(String sev) {
        if (sev == null) return 1;
        try {
            int val = Integer.parseInt(sev);
            if (val >= 8) return 5; // Critical
            if (val >= 6) return 4; // High
            if (val >= 4) return 3; // Medium
            if (val >= 2) return 2; // Low
            return 1;
        } catch (NumberFormatException e) {
            String lower = sev.toLowerCase();
            if (lower.contains("crit")) return 5;
            if (lower.contains("high")) return 4;
            if (lower.contains("med")) return 3;
            if (lower.contains("low")) return 2;
            return 1;
        }
    }

    private String mapSeverityIdToLabel(int id) {
        return switch (id) {
            case 5 -> "critical";
            case 4 -> "high";
            case 3 -> "medium";
            case 2 -> "low";
            default -> "informational";
        };
    }

    private String normalizeAction(String act) {
        if (act == null) return "informational";
        String lower = act.toLowerCase();
        if (lower.contains("deny") || lower.contains("denied") || lower.contains("block") || lower.contains("drop")) {
            return "blocked";
        }
        if (lower.contains("permit") || lower.contains("allow") || lower.contains("accept") || lower.contains("pass")) {
            return "allowed";
        }
        return lower;
    }

    private String parseCefTimestamp(String rt) {
        if (rt == null) return Instant.now().toString();
        try {
            long epoch = Long.parseLong(rt);
            if (rt.length() == 13) {
                return Instant.ofEpochMilli(epoch).toString();
            } else if (rt.length() == 10) {
                return Instant.ofEpochSecond(epoch).toString();
            }
        } catch (NumberFormatException ignored) {}
        return Instant.now().toString();
    }
}
