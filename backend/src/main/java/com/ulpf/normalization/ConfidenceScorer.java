package com.ulpf.normalization;

import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class ConfidenceScorer {

    public double calculateAverageConfidence(Map<String, Double> fieldConfidences) {
        if (fieldConfidences == null || fieldConfidences.isEmpty()) {
            return 0.0;
        }
        double sum = 0.0;
        int count = 0;
        for (Double score : fieldConfidences.values()) {
            if (score != null) {
                sum += score;
                count++;
            }
        }
        if (count == 0) {
            return 0.0;
        }
        double avg = sum / count;
        return Math.round(avg * 1000.0) / 1000.0;
    }

    public String getConfidenceTier(double score) {
        if (score >= 0.90) {
            return "HIGH";
        } else if (score >= 0.70) {
            return "MEDIUM";
        } else {
            return "LOW";
        }
    }
}
