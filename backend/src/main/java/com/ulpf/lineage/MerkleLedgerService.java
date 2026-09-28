package com.ulpf.lineage;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.ulpf.domain.MerkleBatch;
import com.ulpf.domain.NormalizedEvent;
import com.ulpf.domain.RawEvent;
import com.ulpf.repository.MerkleBatchRepository;
import com.ulpf.repository.NormalizedEventRepository;
import com.ulpf.repository.RawEventRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class MerkleLedgerService {

    private final RawEventRepository rawEventRepository;
    private final NormalizedEventRepository normalizedEventRepository;
    private final MerkleBatchRepository merkleBatchRepository;

    @Value("${ulpf.ledger.file-path:./data/ledger/merkle-ledger.jsonl}")
    private String ledgerFilePath;

    private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

    @PostConstruct
    public void init() {
        try {
            File file = new File(ledgerFilePath);
            File parent = file.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
                log.info("Created Merkle ledger directory: {}", parent.getAbsolutePath());
            }
        } catch (Exception e) {
            log.warn("Could not create ledger directory: {}", e.getMessage());
        }
    }

    /**
     * Scheduled job to batch uncommitted raw log hashes into a Merkle tree.
     * Default runs hourly, or triggered on demand.
     */
    @Scheduled(cron = "${ulpf.ledger.batch-cron:0 0 * * * *}")
    @Transactional
    public Optional<MerkleBatch> createBatchScheduled() {
        log.info("Running scheduled Merkle batch cycle...");
        return createBatch();
    }

    /**
     * Create a Merkle batch immediately from all currently unbatched raw events.
     */
    @Transactional
    public Optional<MerkleBatch> createBatch() {
        List<RawEvent> unbatched = rawEventRepository.findByMerkleBatchIdIsNullOrderByReceivedAtAsc();
        if (unbatched.isEmpty()) {
            log.info("No unbatched raw events available for Merkle batching");
            return Optional.empty();
        }

        Instant periodStart = unbatched.get(0).getReceivedAt();
        Instant periodEnd = unbatched.get(unbatched.size() - 1).getReceivedAt();
        Instant now = Instant.now();

        String batchId = "BATCH-" + UUID.randomUUID().toString();
        List<String> leafHashes = new ArrayList<>();
        List<Map<String, Object>> leafRecords = new ArrayList<>();

        for (int i = 0; i < unbatched.size(); i++) {
            RawEvent raw = unbatched.get(i);
            String hash = raw.getRawHashSha256();
            leafHashes.add(hash);

            Map<String, Object> leafItem = new HashMap<>();
            leafItem.put("leafIndex", i);
            leafItem.put("rawEventId", raw.getRawEventId());
            leafItem.put("rawHashSha256", hash);
            leafItem.put("receivedAt", raw.getReceivedAt().toString());

            // Check if normalized event exists for this raw event
            Optional<NormalizedEvent> normOpt = normalizedEventRepository.findByRawEventId(raw.getRawEventId());
            normOpt.ifPresent(norm -> leafItem.put("eventId", norm.getEventId()));

            leafRecords.add(leafItem);
        }

        // 1. Build Merkle Tree
        MerkleTree tree = new MerkleTree(leafHashes);
        String merkleRoot = tree.getRoot();

        String leafOrderJson;
        try {
            leafOrderJson = objectMapper.writeValueAsString(leafRecords);
        } catch (Exception e) {
            log.error("Failed to serialize leaf order metadata: {}", e.getMessage());
            leafOrderJson = "[]";
        }

        long count = merkleBatchRepository.count();
        MerkleBatch batch = MerkleBatch.builder()
                .id(batchId)
                .batchNumber(count + 1)
                .periodStart(periodStart)
                .periodEnd(periodEnd)
                .eventCount(unbatched.size())
                .merkleRoot(merkleRoot)
                .leafOrderEventIds(leafOrderJson)
                .createdAt(now)
                .build();

        merkleBatchRepository.save(batch);

        // 2. Append to independent append-only ledger file
        appendBatchToLedgerFile(batch);

        // 3. Update RawEvents and NormalizedEvents with batch ID
        for (RawEvent raw : unbatched) {
            raw.setMerkleBatchId(batchId);
            rawEventRepository.save(raw);

            Optional<NormalizedEvent> normOpt = normalizedEventRepository.findByRawEventId(raw.getRawEventId());
            if (normOpt.isPresent()) {
                NormalizedEvent norm = normOpt.get();
                norm.setMerkleBatchId(batchId);
                normalizedEventRepository.save(norm);
            }
        }

        log.info("Created Merkle Batch {} with {} events, root: {}", batchId, unbatched.size(), merkleRoot);
        return Optional.of(batch);
    }

    /**
     * Append record to the immutable, append-only JSONL ledger file.
     */
    private synchronized void appendBatchToLedgerFile(MerkleBatch batch) {
        try {
            File file = new File(ledgerFilePath);
            File parent = file.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }

            Map<String, Object> lineData = new LinkedHashMap<>();
            lineData.put("batchId", batch.getId());
            lineData.put("batchNumber", batch.getBatchNumber());
            lineData.put("periodStart", batch.getPeriodStart().toString());
            lineData.put("periodEnd", batch.getPeriodEnd().toString());
            lineData.put("eventCount", batch.getEventCount());
            lineData.put("merkleRoot", batch.getMerkleRoot());
            lineData.put("createdAt", batch.getCreatedAt().toString());
            lineData.put("recordType", "MERKLE_BATCH_PUBLISH");

            String jsonLine = objectMapper.writeValueAsString(lineData);

            try (PrintWriter out = new PrintWriter(new FileWriter(file, StandardCharsets.UTF_8, true))) {
                out.println(jsonLine);
            }
            log.info("Appended Merkle batch {} to ledger file {}", batch.getId(), ledgerFilePath);
        } catch (Exception e) {
            log.error("CRITICAL: Failed to append batch {} to ledger file {}: {}", batch.getId(), ledgerFilePath, e.getMessage(), e);
        }
    }

    public List<MerkleBatch> listAllBatches() {
        return merkleBatchRepository.findAllByOrderByCreatedAtDesc();
    }

    public Optional<MerkleBatch> getBatchById(String batchId) {
        return merkleBatchRepository.findById(batchId);
    }

    /**
     * Generate complete exportable audit bundle for a batch.
     */
    public Map<String, Object> exportBatchBundle(String batchId) {
        Optional<MerkleBatch> batchOpt = merkleBatchRepository.findById(batchId);
        if (batchOpt.isEmpty()) {
            throw new IllegalArgumentException("Merkle batch not found: " + batchId);
        }

        MerkleBatch batch = batchOpt.get();
        List<Map<String, Object>> leaves = new ArrayList<>();
        try {
            leaves = objectMapper.readValue(batch.getLeafOrderEventIds(), new TypeReference<List<Map<String, Object>>>() {});
        } catch (Exception ignored) {}

        List<String> leafHashes = new ArrayList<>();
        for (Map<String, Object> leaf : leaves) {
            leafHashes.add((String) leaf.get("rawHashSha256"));
        }

        MerkleTree tree = new MerkleTree(leafHashes);

        Map<String, Object> exportBundle = new LinkedHashMap<>();
        exportBundle.put("auditStandard", "ULPF-MERKLE-AUDIT-v1.0");
        exportBundle.put("batchId", batch.getId());
        exportBundle.put("batchNumber", batch.getBatchNumber());
        exportBundle.put("periodStart", batch.getPeriodStart());
        exportBundle.put("periodEnd", batch.getPeriodEnd());
        exportBundle.put("eventCount", batch.getEventCount());
        exportBundle.put("merkleRoot", batch.getMerkleRoot());
        exportBundle.put("createdAt", batch.getCreatedAt());
        exportBundle.put("verifiedRootMatchesTree", tree.getRoot().equalsIgnoreCase(batch.getMerkleRoot()));
        exportBundle.put("leafEvents", leaves);

        return exportBundle;
    }
}
