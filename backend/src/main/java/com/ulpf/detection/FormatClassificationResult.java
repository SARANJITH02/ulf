package com.ulpf.detection;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FormatClassificationResult {
    private LogFormat format;
    private double confidence;
    private String matchedSignature;
    private String details;
}
