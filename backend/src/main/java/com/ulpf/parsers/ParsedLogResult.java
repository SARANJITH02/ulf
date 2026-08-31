package com.ulpf.parsers;

import com.ulpf.normalization.OcsfSchema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashMap;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ParsedLogResult {
    private boolean success;
    private OcsfSchema normalizedEvent;
    private String parserName;
    private String parserVersion;
    private String formatType;
    @Builder.Default
    private Map<String, Double> fieldConfidence = new HashMap<>();
    private double averageConfidence;
    private String errorMessage;
    @Builder.Default
    private Map<String, Object> extractedFields = new HashMap<>();
}
