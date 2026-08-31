package com.ulpf.inference;

public interface ParserInferenceEngine {
    String getStrategyName();
    InferenceResult infer(String rawLog);
}
