package com.ulpf.validation;

import com.ulpf.normalization.OcsfSchema;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class EventValidator {

    public ValidationResult validate(OcsfSchema event) {
        if (event == null) {
            return ValidationResult.builder()
                    .valid(false)
                    .failureCode("NULL_EVENT")
                    .failureReason("Normalized event object is null")
                    .build();
        }

        List<String> errors = new ArrayList<>();

        if (event.getEventId() == null || event.getEventId().isBlank()) {
            errors.add("Missing required eventId");
        }
        if (event.getRawEventId() == null || event.getRawEventId().isBlank()) {
            errors.add("Missing required rawEventId");
        }
        if (event.getRawHashSha256() == null || event.getRawHashSha256().isBlank()) {
            errors.add("Missing required rawHashSha256");
        }
        if (event.getTimestampUtc() == null || event.getTimestampUtc().isBlank()) {
            errors.add("Missing required timestampUtc");
        }

        // Validate IP syntax if present
        if (event.getSource() != null && event.getSource().getIp() != null) {
            String ip = event.getSource().getIp();
            if (!isValidIp(ip)) {
                errors.add("Invalid source IP format: " + ip);
            }
        }
        if (event.getDestination() != null && event.getDestination().getIp() != null) {
            String ip = event.getDestination().getIp();
            if (!isValidIp(ip)) {
                errors.add("Invalid destination IP format: " + ip);
            }
        }

        if (!errors.isEmpty()) {
            return ValidationResult.builder()
                    .valid(false)
                    .failureCode("VALIDATION_FAILED")
                    .failureReason(String.join("; ", errors))
                    .errorDetails(errors)
                    .build();
        }

        return ValidationResult.builder()
                .valid(true)
                .build();
    }

    private boolean isValidIp(String ip) {
        if (ip == null || ip.isBlank()) return false;
        String trimmed = ip.trim();
        return trimmed.matches("^(?:\\d{1,3}\\.){3}\\d{1,3}$") || trimmed.contains(":");
    }
}
