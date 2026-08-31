package com.ulpf.detection;

import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Component
public class FormatClassifier {

    // RFC5424 pattern: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID ...
    private static final Pattern RFC5424_PATTERN = Pattern.compile("^<\\d{1,3}>1\\s+\\S+\\s+\\S+.*");

    // RFC3164 pattern: <PRI>Mmm dd hh:mm:ss HOSTNAME TAG: msg...
    private static final Pattern RFC3164_PATTERN = Pattern.compile("^<\\d{1,3}>[A-Z][a-z]{2}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2}\\s+.*");

    // Cisco ASA syslog without PRI or with PRI: %ASA-4-106023 or <134>... %ASA-
    private static final Pattern CISCO_ASA_PATTERN = Pattern.compile(".*%ASA-\\d-\\d+:.*");

    // BSD syslog timestamp without PRI: "Aug 30 10:32:21 host ..."
    private static final Pattern BSD_TIMESTAMP_PATTERN = Pattern.compile("^[A-Z][a-z]{2}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2}\\s+.*");

    // CEF pattern: "CEF:0|Vendor|Product|Version|ID|Name|Severity|Extension..."
    private static final Pattern CEF_PATTERN = Pattern.compile(".*CEF:\\s*\\d+\\|.*");

    // LEEF pattern: "LEEF:1.0|Vendor|Product|Version|EventID|..." or LEEF:2.0|...
    private static final Pattern LEEF_PATTERN = Pattern.compile(".*LEEF:\\s*[12]\\.\\d+\\|.*");

    public FormatClassificationResult classify(String rawLog) {
        if (rawLog == null || rawLog.isBlank()) {
            return FormatClassificationResult.builder()
                    .format(LogFormat.UNKNOWN)
                    .confidence(0.0)
                    .matchedSignature("EMPTY_STRING")
                    .details("Log payload is empty or blank")
                    .build();
        }

        String trimmed = rawLog.trim();

        // 1. Check CEF
        if (CEF_PATTERN.matcher(trimmed).matches()) {
            return FormatClassificationResult.builder()
                    .format(LogFormat.CEF)
                    .confidence(0.99)
                    .matchedSignature("CEF_HEADER_PREFIX")
                    .details("ArcSight Common Event Format signature detected")
                    .build();
        }

        // 2. Check LEEF
        if (LEEF_PATTERN.matcher(trimmed).matches()) {
            return FormatClassificationResult.builder()
                    .format(LogFormat.LEEF)
                    .confidence(0.99)
                    .matchedSignature("LEEF_HEADER_PREFIX")
                    .details("Log Event Extended Format (LEEF) signature detected")
                    .build();
        }

        // 3. Check JSON
        if ((trimmed.startsWith("{") && trimmed.endsWith("}")) ||
            (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
            return FormatClassificationResult.builder()
                    .format(LogFormat.JSON)
                    .confidence(0.98)
                    .matchedSignature("JSON_STRUCTURE")
                    .details("Valid JSON envelope boundary detected")
                    .build();
        }

        // 4. Check Syslog RFC5424
        if (RFC5424_PATTERN.matcher(trimmed).matches()) {
            return FormatClassificationResult.builder()
                    .format(LogFormat.SYSLOG_RFC5424)
                    .confidence(0.98)
                    .matchedSignature("RFC5424_PRI_VERSION")
                    .details("Syslog RFC 5424 PRI header with version 1 detected")
                    .build();
        }

        // 5. Check Syslog RFC3164 or Cisco ASA
        if (RFC3164_PATTERN.matcher(trimmed).matches() || CISCO_ASA_PATTERN.matcher(trimmed).matches()) {
            return FormatClassificationResult.builder()
                    .format(LogFormat.SYSLOG_RFC3164)
                    .confidence(0.95)
                    .matchedSignature("RFC3164_PRI_OR_CISCO_FACILITY")
                    .details("Syslog BSD RFC 3164 or Cisco facility header detected")
                    .build();
        }

        if (BSD_TIMESTAMP_PATTERN.matcher(trimmed).matches()) {
            return FormatClassificationResult.builder()
                    .format(LogFormat.SYSLOG_RFC3164)
                    .confidence(0.90)
                    .matchedSignature("BSD_TIMESTAMP_HEADER")
                    .details("BSD timestamp prefix detected")
                    .build();
        }

        // 6. Check CSV / Delimited
        if (trimmed.contains(",") && trimmed.split(",").length >= 5) {
            return FormatClassificationResult.builder()
                    .format(LogFormat.CSV)
                    .confidence(0.85)
                    .matchedSignature("COMMA_DELIMITED_ROW")
                    .details("Multi-column comma-separated record detected")
                    .build();
        }

        return FormatClassificationResult.builder()
                .format(LogFormat.UNKNOWN)
                .confidence(0.30)
                .matchedSignature("UNRECOGNIZED_SIGNATURE")
                .details("No standard perimeter header signature matched; routing to Inference Engine")
                .build();
    }
}
