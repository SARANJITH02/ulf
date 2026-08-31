package com.ulpf.inference;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class SemanticFieldRecognizer {

    private static final Pattern IPV4_PATTERN = Pattern.compile("^\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b$");
    private static final Pattern IP_PORT_SLASH_PATTERN = Pattern.compile("^(?:[a-zA-Z0-9_-]+:)?(?<ip>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})[/:](?<port>\\d{1,5})$");
    private static final Pattern TIMESTAMP_ISO_PATTERN = Pattern.compile("^\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:?\\d{2})?$");
    private static final Pattern TIMESTAMP_BSD_PATTERN = Pattern.compile("^[A-Z][a-z]{2}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2}$");
    private static final Pattern VENDOR_CODE_PATTERN = Pattern.compile("^%?[A-Z0-9]+-\\d+-\\d+$");

    private static final Set<String> PROTOCOLS = new HashSet<>(Arrays.asList(
            "TCP", "UDP", "ICMP", "GRE", "ESP", "AH", "IGMP", "OSPF", "SCTP", "TLS", "HTTP", "HTTPS", "DNS", "SSH"
    ));

    private static final Set<String> ACTIONS = new HashSet<>(Arrays.asList(
            "ALLOW", "ALLOWED", "PERMIT", "PERMITTED", "ACCEPT", "ACCEPTED", "PASS",
            "DENY", "DENIED", "DROP", "DROPPED", "BLOCK", "BLOCKED", "REJECT", "REJECTED", "RESET"
    ));

    private static final Set<String> SEVERITIES = new HashSet<>(Arrays.asList(
            "EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFORMATIONAL", "INFO", "DEBUG", "HIGH", "MEDIUM", "LOW"
    ));

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RecognizedSemanticType {
        private String semanticType;  // IPV4, IP_PORT_PAIR, PORT, PROTOCOL, ACTION, SEVERITY, TIMESTAMP, VENDOR_CODE, USER, HOSTNAME, UNKNOWN
        private String suggestedOcsfPath;
        private double confidence;
        private String extractedValue;
        private String auxiliaryValue; // e.g. extracted port if IP_PORT_PAIR
    }

    public RecognizedSemanticType recognize(String token, String contextHint, int tokenPosition) {
        if (token == null || token.isBlank()) {
            return RecognizedSemanticType.builder()
                    .semanticType("UNKNOWN")
                    .suggestedOcsfPath("extensions.token_" + tokenPosition)
                    .confidence(0.10)
                    .extractedValue(token)
                    .build();
        }

        String clean = token.replaceAll("[\\[\\](),\"';]", "").trim();
        String upper = clean.toUpperCase();

        // 1. Check Key-Value tokens: e.g. src=192.168.1.5, dst=10.0.0.1, proto=TCP
        if (clean.contains("=") && clean.indexOf('=') < clean.length() - 1) {
            String key = clean.substring(0, clean.indexOf('=')).toLowerCase();
            String val = clean.substring(clean.indexOf('=') + 1);
            return recognizeKeyValue(key, val, tokenPosition);
        }

        // 2. Check IP:Port or IP/Port compound token (e.g. inside:192.168.1.5/52100 or 10.0.0.1:443)
        Matcher ipPortMatcher = IP_PORT_SLASH_PATTERN.matcher(clean);
        if (ipPortMatcher.matches()) {
            String ip = ipPortMatcher.group("ip");
            String port = ipPortMatcher.group("port");
            String path = (contextHint != null && contextHint.equalsIgnoreCase("dst")) || tokenPosition > 5
                    ? "destination.ip" : "source.ip";
            return RecognizedSemanticType.builder()
                    .semanticType("IP_PORT_PAIR")
                    .suggestedOcsfPath(path)
                    .confidence(0.98)
                    .extractedValue(ip)
                    .auxiliaryValue(port)
                    .build();
        }

        // 3. Standalone IPv4
        if (IPV4_PATTERN.matcher(clean).matches()) {
            String path = (contextHint != null && contextHint.toLowerCase().contains("dst")) || tokenPosition > 5
                    ? "destination.ip" : "source.ip";
            return RecognizedSemanticType.builder()
                    .semanticType("IPV4")
                    .suggestedOcsfPath(path)
                    .confidence(0.99)
                    .extractedValue(clean)
                    .build();
        }

        // 4. Protocol
        if (PROTOCOLS.contains(upper)) {
            return RecognizedSemanticType.builder()
                    .semanticType("PROTOCOL")
                    .suggestedOcsfPath("network.protocol")
                    .confidence(0.98)
                    .extractedValue(upper)
                    .build();
        }

        // 5. Action
        if (ACTIONS.contains(upper)) {
            return RecognizedSemanticType.builder()
                    .semanticType("ACTION")
                    .suggestedOcsfPath("event.action")
                    .confidence(0.96)
                    .extractedValue(normalizeAction(upper))
                    .build();
        }

        // 6. Severity
        if (SEVERITIES.contains(upper)) {
            return RecognizedSemanticType.builder()
                    .semanticType("SEVERITY")
                    .suggestedOcsfPath("event.severity")
                    .confidence(0.92)
                    .extractedValue(upper.toLowerCase())
                    .build();
        }

        // 7. Port number (1-65535)
        if (clean.matches("^\\d+$")) {
            int port = Integer.parseInt(clean);
            if (port > 0 && port <= 65535) {
                String path = (contextHint != null && contextHint.toLowerCase().contains("dst")) || tokenPosition > 5
                        ? "destination.port" : "source.port";
                return RecognizedSemanticType.builder()
                        .semanticType("PORT")
                        .suggestedOcsfPath(path)
                        .confidence(0.92)
                        .extractedValue(clean)
                        .build();
            }
        }

        // 8. Timestamp
        if (TIMESTAMP_ISO_PATTERN.matcher(clean).matches() || TIMESTAMP_BSD_PATTERN.matcher(clean).matches()) {
            return RecognizedSemanticType.builder()
                    .semanticType("TIMESTAMP")
                    .suggestedOcsfPath("timestampUtc")
                    .confidence(0.95)
                    .extractedValue(clean)
                    .build();
        }

        // 9. Vendor Code (%ASA-4-106023, FGT-001)
        if (VENDOR_CODE_PATTERN.matcher(clean).matches()) {
            return RecognizedSemanticType.builder()
                    .semanticType("VENDOR_CODE")
                    .suggestedOcsfPath("extensions.vendorCode")
                    .confidence(0.95)
                    .extractedValue(clean)
                    .build();
        }

        return RecognizedSemanticType.builder()
                .semanticType("STRING")
                .suggestedOcsfPath("extensions.token_" + tokenPosition)
                .confidence(0.60)
                .extractedValue(clean)
                .build();
    }

    private RecognizedSemanticType recognizeKeyValue(String key, String val, int tokenPosition) {
        String cleanVal = val.replaceAll("[\\[\\](),\"';]", "").trim();
        String lKey = key.toLowerCase();

        if (lKey.equals("src") || lKey.equals("srcip") || lKey.equals("source_ip") || lKey.equals("src_ip")) {
            return RecognizedSemanticType.builder()
                    .semanticType("IPV4")
                    .suggestedOcsfPath("source.ip")
                    .confidence(0.99)
                    .extractedValue(cleanVal)
                    .build();
        }
        if (lKey.equals("dst") || lKey.equals("dstip") || lKey.equals("dest_ip") || lKey.equals("dst_ip")) {
            return RecognizedSemanticType.builder()
                    .semanticType("IPV4")
                    .suggestedOcsfPath("destination.ip")
                    .confidence(0.99)
                    .extractedValue(cleanVal)
                    .build();
        }
        if (lKey.equals("spt") || lKey.equals("srcport") || lKey.equals("src_port") || lKey.equals("source_port")) {
            return RecognizedSemanticType.builder()
                    .semanticType("PORT")
                    .suggestedOcsfPath("source.port")
                    .confidence(0.98)
                    .extractedValue(cleanVal)
                    .build();
        }
        if (lKey.equals("dpt") || lKey.equals("dstport") || lKey.equals("dest_port") || lKey.equals("dst_port")) {
            return RecognizedSemanticType.builder()
                    .semanticType("PORT")
                    .suggestedOcsfPath("destination.port")
                    .confidence(0.98)
                    .extractedValue(cleanVal)
                    .build();
        }
        if (lKey.equals("proto") || lKey.equals("protocol")) {
            return RecognizedSemanticType.builder()
                    .semanticType("PROTOCOL")
                    .suggestedOcsfPath("network.protocol")
                    .confidence(0.98)
                    .extractedValue(cleanVal.toUpperCase())
                    .build();
        }
        if (lKey.equals("act") || lKey.equals("action") || lKey.equals("status")) {
            return RecognizedSemanticType.builder()
                    .semanticType("ACTION")
                    .suggestedOcsfPath("event.action")
                    .confidence(0.96)
                    .extractedValue(normalizeAction(cleanVal))
                    .build();
        }
        if (lKey.equals("user") || lKey.equals("username") || lKey.equals("usr")) {
            return RecognizedSemanticType.builder()
                    .semanticType("USER")
                    .suggestedOcsfPath("source.user")
                    .confidence(0.95)
                    .extractedValue(cleanVal)
                    .build();
        }

        return RecognizedSemanticType.builder()
                .semanticType("KEY_VALUE")
                .suggestedOcsfPath("extensions." + key)
                .confidence(0.85)
                .extractedValue(cleanVal)
                .build();
    }

    private String normalizeAction(String act) {
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
