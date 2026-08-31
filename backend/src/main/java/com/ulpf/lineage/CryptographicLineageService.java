package com.ulpf.lineage;

import com.ulpf.domain.NormalizedEvent;
import com.ulpf.domain.RawEvent;
import com.ulpf.repository.NormalizedEventRepository;
import com.ulpf.repository.RawEventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class CryptographicLineageService {

    private final RawEventRepository rawEventRepository;
    private final NormalizedEventRepository normalizedEventRepository;

    /**
     * Compute bit-exact SHA-256 digest of the raw log string before any processing.
     */
    public String computeSha256(String rawMessage) {
        if (rawMessage == null) {
            rawMessage = "";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(rawMessage.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available in JVM", e);
        }
    }

    /**
     * Generate immutable Raw Event ID: RAW-{sha256prefix16}
     */
    public String generateRawEventId(String sha256Hash) {
        String prefix = (sha256Hash != null && sha256Hash.length() >= 16)
                ? sha256Hash.substring(0, 16)
                : UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        return "RAW-" + prefix;
    }

    /**
     * Generate Canonical Normalized Event ID: ULPF-{UUID}
     */
    public String generateNormalizedEventId() {
        return "ULPF-" + UUID.randomUUID().toString();
    }

    /**
     * Re-hash stored raw log and verify cryptographic integrity against both
     * RawEvent and NormalizedEvent hashes.
     */
    @Transactional(readOnly = true)
    public IntegrityVerificationResult verifyIntegrity(String eventId) {
        Optional<NormalizedEvent> normOpt = normalizedEventRepository.findByEventId(eventId);
        if (normOpt.isEmpty()) {
            return IntegrityVerificationResult.builder()
                    .eventId(eventId)
                    .verified(false)
                    .checkedAt(Instant.now())
                    .statusMessage("Normalized event not found: " + eventId)
                    .build();
        }

        NormalizedEvent norm = normOpt.get();
        Optional<RawEvent> rawOpt = rawEventRepository.findByRawEventId(norm.getRawEventId());
        if (rawOpt.isEmpty()) {
            return IntegrityVerificationResult.builder()
                    .eventId(eventId)
                    .rawEventId(norm.getRawEventId())
                    .verified(false)
                    .normalizedStoredHash(norm.getRawHashSha256())
                    .checkedAt(Instant.now())
                    .statusMessage("Associated raw event record not found for rawEventId: " + norm.getRawEventId())
                    .build();
        }

        RawEvent raw = rawOpt.get();
        String recomputed = computeSha256(raw.getRawMessage());
        boolean rawMatches = recomputed.equalsIgnoreCase(raw.getRawHashSha256());
        boolean normMatches = recomputed.equalsIgnoreCase(norm.getRawHashSha256());
        boolean verified = rawMatches && normMatches;

        String status = verified
                ? "Cryptographic verification SUCCESS. Bit-perfect integrity confirmed across raw and normalized records."
                : "Cryptographic verification FAILED. Hash mismatch detected between raw payload and recorded digests.";

        return IntegrityVerificationResult.builder()
                .eventId(norm.getEventId())
                .rawEventId(raw.getRawEventId())
                .verified(verified)
                .storedRawHash(raw.getRawHashSha256())
                .recomputedRawHash(recomputed)
                .normalizedStoredHash(norm.getRawHashSha256())
                .rawByteLength(raw.getRawMessage().getBytes(StandardCharsets.UTF_8).length)
                .checkedAt(Instant.now())
                .statusMessage(status)
                .parserName(norm.getParserName())
                .parserVersion(norm.getParserVersion())
                .schemaVersion("1.1.0-ocsf")
                .build();
    }
}
