package com.ulpf.lineage;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IntegrityVerificationResult {
    private String eventId;
    private String rawEventId;
    private boolean verified;
    private String storedRawHash;
    private String recomputedRawHash;
    private String normalizedStoredHash;
    private int rawByteLength;
    private Instant checkedAt;
    private String statusMessage;
    private String parserName;
    private String parserVersion;
    private String schemaVersion;
}
