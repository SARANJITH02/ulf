package com.ulpf.lineage;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ulpf.domain.MerkleBatch;
import com.ulpf.domain.NormalizedEvent;
import com.ulpf.domain.RawEvent;
import com.ulpf.repository.MerkleBatchRepository;
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
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class CryptographicLineageService {

    private final RawEventRepository rawEventRepository;
    private final NormalizedEventRepository normalizedEventRepository;
    private final MerkleBatchRepository merkleBatchRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();

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
     * Generate immutable Raw Event ID: RAW-{sha256prefix8}-{uuidSuffix}
     */
    public String generateRawEventId(String sha256Hash) {
        String hashPrefix = (sha256Hash != null && sha256Hash.length() >= 8)
                ? sha256Hash.substring(0, 8)
                : "00000000";
        String uniqueSuffix = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        return "RAW-" + hashPrefix + "-" + uniqueSuffix;
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

    /**
     * Verify event inclusion in a published Merkle batch via cryptographic proof path.
     */
    @Transactional(readOnly = true)
    public MerkleInclusionResult verifyInclusion(String eventId) {
        Optional<NormalizedEvent> normOpt = normalizedEventRepository.findByEventId(eventId);
        String rawEventId;
        String rawHash;
        String batchId = null;

        if (normOpt.isPresent()) {
            NormalizedEvent norm = normOpt.get();
            rawEventId = norm.getRawEventId();
            rawHash = norm.getRawHashSha256();
            batchId = norm.getMerkleBatchId();
        } else {
            Optional<RawEvent> rawOpt = rawEventRepository.findByRawEventId(eventId);
            if (rawOpt.isEmpty()) {
                return MerkleInclusionResult.builder()
                        .eventId(eventId)
                        .verified(false)
                        .verifiedAt(Instant.now())
                        .statusMessage("Event not found in repository: " + eventId)
                        .build();
            }
            RawEvent raw = rawOpt.get();
            rawEventId = raw.getRawEventId();
            rawHash = raw.getRawHashSha256();
            batchId = raw.getMerkleBatchId();
        }

        if (batchId == null || batchId.isBlank()) {
            return MerkleInclusionResult.builder()
                    .eventId(eventId)
                    .rawEventId(rawEventId)
                    .rawHashSha256(rawHash)
                    .verified(false)
                    .verifiedAt(Instant.now())
                    .statusMessage("Event has not been batched into a Merkle ledger yet (pending next batch cycle)")
                    .build();
        }

        Optional<MerkleBatch> batchOpt = merkleBatchRepository.findById(batchId);
        if (batchOpt.isEmpty()) {
            return MerkleInclusionResult.builder()
                    .eventId(eventId)
                    .rawEventId(rawEventId)
                    .rawHashSha256(rawHash)
                    .merkleBatchId(batchId)
                    .verified(false)
                    .verifiedAt(Instant.now())
                    .statusMessage("Referenced Merkle batch record not found: " + batchId)
                    .build();
        }

        MerkleBatch batch = batchOpt.get();
        List<Map<String, Object>> leafRecords;
        try {
            leafRecords = objectMapper.readValue(batch.getLeafOrderEventIds(), new TypeReference<List<Map<String, Object>>>() {});
        } catch (Exception e) {
            return MerkleInclusionResult.builder()
                    .eventId(eventId)
                    .rawEventId(rawEventId)
                    .rawHashSha256(rawHash)
                    .merkleBatchId(batchId)
                    .verified(false)
                    .verifiedAt(Instant.now())
                    .statusMessage("Failed to parse batch leaf order data: " + e.getMessage())
                    .build();
        }

        List<String> leafHashes = new ArrayList<>();
        int targetIndex = -1;

        for (int i = 0; i < leafRecords.size(); i++) {
            Map<String, Object> item = leafRecords.get(i);
            String h = (String) item.get("rawHashSha256");
            leafHashes.add(h);
            String itemRawId = (String) item.get("rawEventId");
            String itemEventId = (String) item.get("eventId");
            if (rawEventId.equalsIgnoreCase(itemRawId) || (itemEventId != null && eventId.equalsIgnoreCase(itemEventId))) {
                targetIndex = i;
            }
        }

        if (targetIndex == -1) {
            return MerkleInclusionResult.builder()
                    .eventId(eventId)
                    .rawEventId(rawEventId)
                    .rawHashSha256(rawHash)
                    .merkleBatchId(batchId)
                    .verified(false)
                    .verifiedAt(Instant.now())
                    .statusMessage("Event hash not found among batch leaf hashes")
                    .build();
        }

        // Reconstruct Merkle tree from published leaf order
        MerkleTree tree = new MerkleTree(leafHashes);
        List<MerkleTree.ProofNode> proof = tree.generateProof(targetIndex);
        boolean proofMatchesRoot = MerkleTree.verifyProof(rawHash, proof, batch.getMerkleRoot());
        boolean rootMatchesBatch = tree.getRoot().equalsIgnoreCase(batch.getMerkleRoot());
        boolean verified = proofMatchesRoot && rootMatchesBatch;

        String statusMsg = verified
                ? "Merkle inclusion proof VERIFIED. Event cryptographically proven as part of published Batch " + batchId
                : "Merkle inclusion proof FAILED. Computed proof does not resolve to batch root.";

        return MerkleInclusionResult.builder()
                .eventId(eventId)
                .rawEventId(rawEventId)
                .rawHashSha256(rawHash)
                .merkleBatchId(batchId)
                .merkleRoot(batch.getMerkleRoot())
                .leafIndex(targetIndex)
                .totalLeaves(leafHashes.size())
                .proofPath(proof)
                .verified(verified)
                .batchedAt(batch.getCreatedAt())
                .verifiedAt(Instant.now())
                .statusMessage(statusMsg)
                .build();
    }
}

