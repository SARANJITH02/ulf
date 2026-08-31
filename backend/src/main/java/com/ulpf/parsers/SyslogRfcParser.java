package com.ulpf.parsers;

import com.ulpf.detection.LogFormat;
import com.ulpf.normalization.OcsfSchema;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
@Slf4j
public class SyslogRfcParser implements ParserPlugin {

    private boolean active = true;

    // Cisco ASA patterns
    // e.g. %ASA-4-106023: Deny tcp src inside:192.168.1.5/52100 dst outside:10.10.10.20/443 by access-group "access-group-dmz-01"
    private static final Pattern CISCO_ASA_CONN_PATTERN = Pattern.compile(
            "(?:<(?<pri>\\d+)>)?(?:(?<month>[A-Z][a-z]{2})\\s+(?<day>\\d+)\\s+(?<time>\\d{2}:\\d{2}:\\d{2}))?\\s*(?:(?<host>\\S+)\\s+)?%(?<vendorCode>ASA-\\d-\\d+):\\s+(?<action>\\w+)\\s+(?<protocol>\\w+)\\s+src\\s+(?:(?<srcZone>\\w+):)?(?<srcIp>\\d+\\.\\d+\\.\\d+\\.\\d+)/(?<srcPort>\\d+)\\s+dst\\s+(?:(?<dstZone>\\w+):)?(?<dstIp>\\d+\\.\\d+\\.\\d+\\.\\d+)/(?<dstPort>\\d+)(?:\\s+by\\s+access-group\\s+(?:\"(?<ruleId>[^\"]+)\"|(?<ruleIdSimple>\\S+)))?.*",
            Pattern.CASE_INSENSITIVE
    );

    // Linux iptables / kernel drop pattern
    // e.g. <13>Aug 30 10:32:21 fw01 kernel: DROP IN=eth0 OUT=eth1 SRC=192.168.1.50 DST=10.0.0.10 PROTO=TCP SPT=55432 DPT=22
    private static final Pattern IPTABLES_PATTERN = Pattern.compile(
            "(?:<(?<pri>\\d+)>)?(?:(?<month>[A-Z][a-z]{2})\\s+(?<day>\\d+)\\s+(?<time>\\d{2}:\\d{2}:\\d{2}))?\\s*(?:(?<host>\\S+)\\s+)?(?:kernel:\\s+)?(?<action>DROP|ACCEPT|REJECT|ALLOW|BLOCK)?.*\\bSRC=(?<srcIp>\\d+\\.\\d+\\.\\d+\\.\\d+)\\b.*\\bDST=(?<dstIp>\\d+\\.\\d+\\.\\d+\\.\\d+)\\b.*\\bPROTO=(?<protocol>\\w+)\\b(?:.*\\bSPT=(?<srcPort>\\d+)\\b)?(?:.*\\bDPT=(?<dstPort>\\d+)\\b)?.*",
            Pattern.CASE_INSENSITIVE
    );

    // RFC 5424 pattern: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
    private static final Pattern RFC5424_PATTERN = Pattern.compile(
            "^<(?<pri>\\d{1,3})>1\\s+(?<timestamp>\\S+)\\s+(?<hostname>\\S+)\\s+(?<appname>\\S+)\\s+(?<procid>\\S+)\\s+(?<msgid>\\S+)(?:\\s+(?<sd>\\[.*?\\]))?\\s+(?<msg>.*)$"
    );

    // Generic key=value extraction inside syslog messages
    private static final Pattern KV_PATTERN = Pattern.compile("([a-zA-Z0-9_.-]+)=([\"']?)([^\"'\\s]+)\\2");

    @Override
    public String getName() {
        return "syslog_rfc_parser";
    }

    @Override
    public String getDisplayName() {
        return "Syslog RFC 5424 / 3164 & Cisco Parser";
    }

    @Override
    public String getVersion() {
        return "1.0.0";
    }

    @Override
    public String getFormatType() {
        return "SYSLOG";
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
        if (detectedFormat == LogFormat.SYSLOG_RFC5424 || detectedFormat == LogFormat.SYSLOG_RFC3164) {
            return true;
        }
        return rawMessage.contains("%ASA-") || rawMessage.contains("IPTABLES") || rawMessage.contains("kernel:") || rawMessage.startsWith("<");
    }

    @Override
    public ParsedLogResult parse(String rawMessage) {
        if (rawMessage == null || rawMessage.isBlank()) {
            return ParsedLogResult.builder()
                    .success(false)
                    .errorMessage("Empty syslog message")
                    .build();
        }

        try {
            // 1. Try Cisco ASA
            Matcher ciscoMatcher = CISCO_ASA_CONN_PATTERN.matcher(rawMessage.trim());
            if (ciscoMatcher.matches()) {
                return parseCiscoAsa(ciscoMatcher, rawMessage);
            }

            // 2. Try IPtables / Kernel Drop
            Matcher ipMatcher = IPTABLES_PATTERN.matcher(rawMessage.trim());
            if (ipMatcher.matches()) {
                return parseIptables(ipMatcher, rawMessage);
            }

            // 3. Try RFC5424
            Matcher rfc5424Matcher = RFC5424_PATTERN.matcher(rawMessage.trim());
            if (rfc5424Matcher.matches()) {
                return parseRfc5424(rfc5424Matcher, rawMessage);
            }

            // 4. Fallback: Parse generic Syslog with embedded KV tokens
            return parseGenericSyslog(rawMessage);

        } catch (Exception e) {
            log.error("Failed parsing syslog message: {}", rawMessage, e);
            return ParsedLogResult.builder()
                    .success(false)
                    .parserName(getName())
                    .parserVersion(getVersion())
                    .formatType(getFormatType())
                    .errorMessage("Syslog parsing error: " + e.getMessage())
                    .build();
        }
    }

    private ParsedLogResult parseCiscoAsa(Matcher m, String rawMessage) {
        Map<String, Double> confidence = new HashMap<>();
        Map<String, Object> extensions = new HashMap<>();

        String action = normalizeAction(m.group("action"));
        confidence.put("event.action", 0.98);

        String protocol = m.group("protocol").toUpperCase();
        confidence.put("network.protocol", 0.99);

        String srcIp = m.group("srcIp");
        confidence.put("source.ip", 0.99);

        int srcPort = Integer.parseInt(m.group("srcPort"));
        confidence.put("source.port", 0.99);

        String dstIp = m.group("dstIp");
        confidence.put("destination.ip", 0.99);

        int dstPort = Integer.parseInt(m.group("dstPort"));
        confidence.put("destination.port", 0.99);

        String vendorCode = "%" + m.group("vendorCode");
        extensions.put("vendorCode", vendorCode);

        String ruleId = m.group("ruleId") != null ? m.group("ruleId") : m.group("ruleIdSimple");
        if (ruleId != null) {
            extensions.put("ciscoRuleId", ruleId);
        }

        String host = m.group("host") != null ? m.group("host") : "cisco-asa";
        confidence.put("observer.hostname", 0.95);

        String timestamp = parseTimestamp(m.group("month"), m.group("day"), m.group("time"));

        OcsfSchema ocsf = OcsfSchema.builder()
                .timestampUtc(timestamp)
                .event(OcsfSchema.EventDetail.builder()
                        .category("network_traffic")
                        .type("firewall")
                        .action(action)
                        .severity(action.equalsIgnoreCase("blocked") || action.equalsIgnoreCase("denied") ? "high" : "informational")
                        .severityId(action.equalsIgnoreCase("blocked") || action.equalsIgnoreCase("denied") ? 4 : 1)
                        .message("Cisco ASA firewall traffic: " + action + " " + protocol + " connection")
                        .build())
                .source(OcsfSchema.Endpoint.builder()
                        .ip(srcIp)
                        .port(srcPort)
                        .zone(m.group("srcZone"))
                        .build())
                .destination(OcsfSchema.Endpoint.builder()
                        .ip(dstIp)
                        .port(dstPort)
                        .zone(m.group("dstZone"))
                        .build())
                .network(OcsfSchema.NetworkDetail.builder()
                        .protocol(protocol)
                        .direction("egress")
                        .build())
                .observer(OcsfSchema.ObserverDetail.builder()
                        .vendor("Cisco")
                        .product("ASA-Firewall")
                        .hostname(host)
                        .build())
                .raw(OcsfSchema.RawDetail.builder()
                        .message(rawMessage)
                        .format("SYSLOG")
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
                .formatType("SYSLOG")
                .fieldConfidence(confidence)
                .build();
    }

    private ParsedLogResult parseIptables(Matcher m, String rawMessage) {
        Map<String, Double> confidence = new HashMap<>();
        Map<String, Object> extensions = new HashMap<>();

        String rawAction = m.group("action");
        String action = rawAction != null ? normalizeAction(rawAction) : "blocked";
        confidence.put("event.action", 0.95);

        String srcIp = m.group("srcIp");
        confidence.put("source.ip", 0.99);

        String dstIp = m.group("dstIp");
        confidence.put("destination.ip", 0.99);

        String protocol = m.group("protocol") != null ? m.group("protocol").toUpperCase() : "TCP";
        confidence.put("network.protocol", 0.95);

        Integer srcPort = m.group("srcPort") != null ? Integer.parseInt(m.group("srcPort")) : null;
        if (srcPort != null) confidence.put("source.port", 0.98);

        Integer dstPort = m.group("dstPort") != null ? Integer.parseInt(m.group("dstPort")) : null;
        if (dstPort != null) confidence.put("destination.port", 0.98);

        String host = m.group("host") != null ? m.group("host") : "linux-fw";
        String timestamp = parseTimestamp(m.group("month"), m.group("day"), m.group("time"));

        OcsfSchema ocsf = OcsfSchema.builder()
                .timestampUtc(timestamp)
                .event(OcsfSchema.EventDetail.builder()
                        .category("network_traffic")
                        .type("firewall")
                        .action(action)
                        .severity(action.equalsIgnoreCase("blocked") ? "medium" : "informational")
                        .severityId(action.equalsIgnoreCase("blocked") ? 3 : 1)
                        .message("Linux kernel packet filter: " + action + " " + protocol)
                        .build())
                .source(OcsfSchema.Endpoint.builder()
                        .ip(srcIp)
                        .port(srcPort)
                        .build())
                .destination(OcsfSchema.Endpoint.builder()
                        .ip(dstIp)
                        .port(dstPort)
                        .build())
                .network(OcsfSchema.NetworkDetail.builder()
                        .protocol(protocol)
                        .build())
                .observer(OcsfSchema.ObserverDetail.builder()
                        .vendor("Linux")
                        .product("iptables")
                        .hostname(host)
                        .build())
                .raw(OcsfSchema.RawDetail.builder()
                        .message(rawMessage)
                        .format("SYSLOG")
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
                .formatType("SYSLOG")
                .fieldConfidence(confidence)
                .build();
    }

    private ParsedLogResult parseRfc5424(Matcher m, String rawMessage) {
        Map<String, Double> confidence = new HashMap<>();
        Map<String, Object> extensions = new HashMap<>();

        String timestamp = m.group("timestamp");
        String hostname = m.group("hostname");
        String appName = m.group("appname");
        String msg = m.group("msg");

        confidence.put("observer.hostname", 0.95);

        // Extract key-value from msg
        Map<String, String> kv = extractKeyValues(msg);
        extensions.putAll(kv);

        String srcIp = kv.getOrDefault("src", kv.getOrDefault("src_ip", kv.getOrDefault("source_ip", null)));
        String dstIp = kv.getOrDefault("dst", kv.getOrDefault("dst_ip", kv.getOrDefault("dest_ip", null)));
        String proto = kv.getOrDefault("proto", kv.getOrDefault("protocol", "TCP")).toUpperCase();
        String act = kv.getOrDefault("action", kv.getOrDefault("act", "allowed"));

        if (srcIp != null) confidence.put("source.ip", 0.95);
        if (dstIp != null) confidence.put("destination.ip", 0.95);
        confidence.put("event.action", 0.90);

        Integer srcPort = parsePort(kv.getOrDefault("spt", kv.getOrDefault("src_port", null)));
        Integer dstPort = parsePort(kv.getOrDefault("dpt", kv.getOrDefault("dst_port", null)));

        OcsfSchema ocsf = OcsfSchema.builder()
                .timestampUtc(timestamp.contains("T") ? timestamp : Instant.now().toString())
                .event(OcsfSchema.EventDetail.builder()
                        .category("network_traffic")
                        .type("syslog_rfc5424")
                        .action(normalizeAction(act))
                        .severity("informational")
                        .severityId(1)
                        .message(msg)
                        .build())
                .source(OcsfSchema.Endpoint.builder()
                        .ip(srcIp)
                        .port(srcPort)
                        .build())
                .destination(OcsfSchema.Endpoint.builder()
                        .ip(dstIp)
                        .port(dstPort)
                        .build())
                .network(OcsfSchema.NetworkDetail.builder()
                        .protocol(proto)
                        .build())
                .observer(OcsfSchema.ObserverDetail.builder()
                        .vendor("GenericSyslog")
                        .product(appName)
                        .hostname(hostname)
                        .build())
                .raw(OcsfSchema.RawDetail.builder()
                        .message(rawMessage)
                        .format("SYSLOG_RFC5424")
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
                .formatType("SYSLOG_RFC5424")
                .fieldConfidence(confidence)
                .build();
    }

    private ParsedLogResult parseGenericSyslog(String rawMessage) {
        Map<String, Double> confidence = new HashMap<>();
        Map<String, Object> extensions = new HashMap<>();
        Map<String, String> kv = extractKeyValues(rawMessage);
        extensions.putAll(kv);

        String srcIp = kv.getOrDefault("src", kv.getOrDefault("srcip", kv.getOrDefault("src_ip", null)));
        String dstIp = kv.getOrDefault("dst", kv.getOrDefault("dstip", kv.getOrDefault("dst_ip", null)));
        String action = normalizeAction(kv.getOrDefault("action", kv.getOrDefault("act", "informational")));
        String proto = kv.getOrDefault("proto", kv.getOrDefault("protocol", "IP")).toUpperCase();

        if (srcIp != null) confidence.put("source.ip", 0.90);
        if (dstIp != null) confidence.put("destination.ip", 0.90);
        confidence.put("event.action", 0.85);

        Integer srcPort = parsePort(kv.getOrDefault("spt", kv.getOrDefault("srcport", null)));
        Integer dstPort = parsePort(kv.getOrDefault("dpt", kv.getOrDefault("dstport", null)));

        OcsfSchema ocsf = OcsfSchema.builder()
                .timestampUtc(Instant.now().toString())
                .event(OcsfSchema.EventDetail.builder()
                        .category("network_traffic")
                        .type("syslog")
                        .action(action)
                        .severity("informational")
                        .severityId(1)
                        .message(rawMessage)
                        .build())
                .source(OcsfSchema.Endpoint.builder().ip(srcIp).port(srcPort).build())
                .destination(OcsfSchema.Endpoint.builder().ip(dstIp).port(dstPort).build())
                .network(OcsfSchema.NetworkDetail.builder().protocol(proto).build())
                .observer(OcsfSchema.ObserverDetail.builder().vendor("Syslog").product("Generic").build())
                .raw(OcsfSchema.RawDetail.builder().message(rawMessage).format("SYSLOG").build())
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
                .formatType("SYSLOG")
                .fieldConfidence(confidence)
                .build();
    }

    private Map<String, String> extractKeyValues(String text) {
        Map<String, String> map = new HashMap<>();
        if (text == null) return map;
        Matcher m = KV_PATTERN.matcher(text);
        while (m.find()) {
            map.put(m.group(1), m.group(3));
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

    private String normalizeAction(String act) {
        if (act == null) return "informational";
        String lower = act.toLowerCase();
        if (lower.contains("deny") || lower.contains("denied") || lower.contains("block") || lower.contains("drop") || lower.contains("reject")) {
            return "blocked";
        }
        if (lower.contains("permit") || lower.contains("allow") || lower.contains("accept") || lower.contains("pass")) {
            return "allowed";
        }
        return lower;
    }

    private String parseTimestamp(String month, String day, String time) {
        if (month == null || day == null || time == null) {
            return Instant.now().toString();
        }
        try {
            int year = ZonedDateTime.now(ZoneOffset.UTC).getYear();
            String dateStr = String.format("%d %s %02d %s", year, month, Integer.parseInt(day), time);
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy MMM dd HH:mm:ss", Locale.ENGLISH);
            ZonedDateTime zdt = ZonedDateTime.parse(dateStr, formatter.withZone(ZoneOffset.UTC));
            return zdt.toInstant().toString();
        } catch (Exception e) {
            return Instant.now().toString();
        }
    }
}
