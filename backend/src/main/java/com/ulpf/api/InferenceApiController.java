package com.ulpf.api;

import com.ulpf.inference.DrainInferenceEngine;
import com.ulpf.inference.InferenceResult;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/infer")
@RequiredArgsConstructor
public class InferenceApiController {

    private final DrainInferenceEngine inferenceEngine;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class InferRequest {
        private String logSample;
        private String sample;
        private String rawMessage;
    }

    @PostMapping
    public ResponseEntity<InferenceResult> inferUnknownLog(@RequestBody InferRequest request) {
        String sample = request.getLogSample() != null ? request.getLogSample() :
                (request.getSample() != null ? request.getSample() : request.getRawMessage());

        if (sample == null || sample.isBlank()) {
            return ResponseEntity.badRequest().build();
        }

        InferenceResult result = inferenceEngine.infer(sample.trim());
        return ResponseEntity.ok(result);
    }
}
