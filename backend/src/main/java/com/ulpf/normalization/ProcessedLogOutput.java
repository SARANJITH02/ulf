package com.ulpf.normalization;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProcessedLogOutput {
    private boolean success;
    private String eventId;
    private String rawEventId;
    private String rawHashSha256;
    private OcsfSchema normalizedEvent;
    private String format;
    private String parserName;
    private double averageConfidence;
    private double processingLatencyMs;
    private String errorMessage;
}
