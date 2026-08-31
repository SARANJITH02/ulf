package com.ulpf.parsers;

import com.ulpf.detection.LogFormat;
import com.ulpf.domain.FieldMapping;
import com.ulpf.normalization.OcsfSchema;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class DynamicGeneratedParser implements ParserPlugin {

    @Getter
    private final String name;
    @Getter
    private final String displayName;
    @Getter
    private final String version;
    @Getter
    private final String formatType;
    @Getter
    private final String templatePattern;
    @Getter
    private final String regexPatternString;
    private final Pattern compiledPattern;
    private final List<FieldMapping> fieldMappings;
    @Getter
    private final double confidenceScore;

    @Getter
    @Setter
    private boolean active = true;

    public DynamicGeneratedParser(String name,
                                  String displayName,
                                  String version,
                                  String formatType,
                                  String templatePattern,
                                  String regexPatternString,
                                  List<FieldMapping> fieldMappings,
                                  double confidenceScore) {
        this.name = name;
        this.displayName = displayName != null ? displayName : name;
        this.version = version != null ? version : "1.0";
        this.formatType = formatType != null ? formatType : "CUSTOM";
        this.templatePattern = templatePattern;
        this.regexPatternString = regexPatternString;
        this.fieldMappings = fieldMappings != null ? fieldMappings : Collections.emptyList();
        this.confidenceScore = confidenceScore;
        this.compiledPattern = Pattern.compile(regexPatternString, Pattern.CASE_INSENSITIVE);
    }

    @Override
    public boolean canParse(String rawMessage, LogFormat detectedFormat) {
        if (!active || rawMessage == null) return false;
        try {
            return compiledPattern.matcher(rawMessage.trim()).matches();
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public ParsedLogResult parse(String rawMessage) {
        if (rawMessage == null || rawMessage.isBlank()) {
            return ParsedLogResult.builder().success(false).errorMessage("Empty payload").build();
        }

        try {
            Matcher m = compiledPattern.matcher(rawMessage.trim());
            if (!m.matches()) {
                return ParsedLogResult.builder()
                        .success(false)
                        .errorMessage("Dynamic regex pattern did not match payload")
                        .build();
            }

            Map<String, Double> confidence = new HashMap<>();
            Map<String, Object> extensions = new HashMap<>();

            String srcIp = null;
            Integer srcPort = null;
            String dstIp = null;
            Integer dstPort = null;
            String proto = "TCP";
            String action = "allowed";
            String timestamp = Instant.now().toString();
            String user = null;

            for (FieldMapping mapping : fieldMappings) {
                String slotName = mapping.getSlotName();
                String val = null;
                try {
                    val = m.group(slotName);
                } catch (IllegalArgumentException e) {
                    try {
                        val = m.group(slotName.replace("_", ""));
                    } catch (IllegalArgumentException ignored) {}
                }

                if (val == null) continue;

                val = val.replaceAll("[\\[\\](),\"';]", "").trim();
                String path = mapping.getCanonicalPath();
                double conf = mapping.getConfidence() != null ? mapping.getConfidence() : confidenceScore;
                confidence.put(path, conf);

                if (path.equals("source.ip")) {
                    srcIp = extractIpOnly(val);
                    if (val.contains(":") || val.contains("/")) {
                        Integer p = extractPortOnly(val);
                        if (p != null) srcPort = p;
                    }
                } else if (path.equals("destination.ip")) {
                    dstIp = extractIpOnly(val);
                    if (val.contains(":") || val.contains("/")) {
                        Integer p = extractPortOnly(val);
                        if (p != null) dstPort = p;
                    }
                } else if (path.equals("source.port")) {
                    Integer p = extractPortOnly(val);
                    if (p != null) srcPort = p;
                } else if (path.equals("destination.port")) {
                    Integer p = extractPortOnly(val);
                    if (p != null) dstPort = p;
                } else if (path.equals("network.protocol")) {
                    proto = val.replaceAll("^[a-zA-Z0-9_.-]+=", "").toUpperCase();
                } else if (path.equals("event.action")) {
                    action = normalizeAction(val.replaceAll("^[a-zA-Z0-9_.-]+=", ""));
                } else if (path.equals("source.user")) {
                    user = val.replaceAll("^[a-zA-Z0-9_.-]+=", "");
                } else if (path.equals("timestampUtc")) {
                    timestamp = val;
                } else {
                    extensions.put(slotName, val);
                }
            }

            OcsfSchema ocsf = OcsfSchema.builder()
                    .timestampUtc(timestamp)
                    .event(OcsfSchema.EventDetail.builder()
                            .category("network_traffic")
                            .type("firewall")
                            .action(action)
                            .severity(action.equalsIgnoreCase("blocked") ? "high" : "informational")
                            .severityId(action.equalsIgnoreCase("blocked") ? 4 : 1)
                            .message("Dynamic Log: " + action + " " + proto)
                            .build())
                    .source(OcsfSchema.Endpoint.builder().ip(srcIp).port(srcPort).user(user).build())
                    .destination(OcsfSchema.Endpoint.builder().ip(dstIp).port(dstPort).build())
                    .network(OcsfSchema.NetworkDetail.builder().protocol(proto).direction("egress").build())
                    .observer(OcsfSchema.ObserverDetail.builder().vendor("DynamicVendor").product(name).build())
                    .raw(OcsfSchema.RawDetail.builder().message(rawMessage).format(formatType).build())
                    .extensions(extensions)
                    .ulpf(OcsfSchema.UlpfMetadata.builder()
                            .parserName(name)
                            .parserVersion(version)
                            .mappingConfidence(confidence)
                            .build())
                    .build();

            return ParsedLogResult.builder()
                    .success(true)
                    .normalizedEvent(ocsf)
                    .parserName(name)
                    .parserVersion(version)
                    .formatType(formatType)
                    .fieldConfidence(confidence)
                    .build();

        } catch (Exception e) {
            log.error("Failed dynamic parsing for {}: {}", name, rawMessage, e);
            return ParsedLogResult.builder()
                    .success(false)
                    .parserName(name)
                    .parserVersion(version)
                    .formatType(formatType)
                    .errorMessage("Dynamic parser exception: " + e.getMessage())
                    .build();
        }
    }

    private String extractIpOnly(String token) {
        String clean = token.replaceAll("^[a-zA-Z0-9_.-]+=", "");
        if (clean.contains(":") && !clean.startsWith("http")) {
            return clean.substring(0, clean.indexOf(':')).replaceAll("^[a-zA-Z0-9_-]+:", "");
        }
        if (clean.contains("/")) {
            return clean.substring(0, clean.indexOf('/')).replaceAll("^[a-zA-Z0-9_-]+:", "");
        }
        return clean.replaceAll("^[a-zA-Z0-9_-]+:", "");
    }

    private Integer extractPortOnly(String token) {
        try {
            String clean = token.replaceAll("^[a-zA-Z0-9_.-]+=", "");
            if (clean.contains(":")) {
                return Integer.parseInt(clean.substring(clean.lastIndexOf(':') + 1));
            }
            if (clean.contains("/")) {
                return Integer.parseInt(clean.substring(clean.lastIndexOf('/') + 1));
            }
            return Integer.parseInt(clean);
        } catch (Exception ignored) {}
        return null;
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
