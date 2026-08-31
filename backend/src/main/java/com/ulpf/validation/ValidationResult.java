package com.ulpf.validation;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ValidationResult {
    private boolean valid;
    private String failureCode; // VALIDATION_FAILED, INVALID_TIMESTAMP, MISSING_REQUIRED_FIELDS, UNRECOGNIZED_FORMAT
    private String failureReason;
    @Builder.Default
    private List<String> errorDetails = new ArrayList<>();
}
