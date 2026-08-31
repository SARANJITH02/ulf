package com.ulpf.inference;

import com.ulpf.domain.FieldMapping;
import com.ulpf.normalization.OcsfSchema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InferenceResult {
    private String rawSample;
    private String minedTemplate;
    private String synthesizedRegex;
    private String suggestedParserName;
    private String suggestedFormat;
    @Builder.Default
    private List<FieldMapping> inferredMappings = new ArrayList<>();
    @Builder.Default
    private Map<String, Double> confidenceMatrix = new HashMap<>();
    private double overallConfidence;
    private String confidenceTier; // HIGH, MEDIUM, LOW
    private boolean recommendedForApproval;
    private OcsfSchema previewNormalizedEvent;
    private String stage1Miner; // "DrainStyleTemplateMiner"
    private String stage2Recognizer; // "DeterministicSemanticFieldRecognizer"
}
