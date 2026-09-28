package com.ulpf;

import com.ulpf.domain.MerkleBatch;
import com.ulpf.domain.RawEvent;
import com.ulpf.lineage.CryptographicLineageService;
import com.ulpf.lineage.MerkleInclusionResult;
import com.ulpf.lineage.MerkleLedgerService;
import com.ulpf.repository.MerkleBatchRepository;
import com.ulpf.repository.NormalizedEventRepository;
import com.ulpf.repository.RawEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("dev")
public class MerkleLedgerServiceTest {

    @Autowired
    private MerkleLedgerService merkleLedgerService;

    @Autowired
    private CryptographicLineageService lineageService;

    @Autowired
    private RawEventRepository rawEventRepository;

    @Autowired
    private NormalizedEventRepository normalizedEventRepository;

    @Autowired
    private MerkleBatchRepository merkleBatchRepository;

    @BeforeEach
    void setUp() {
        rawEventRepository.deleteAll();
        normalizedEventRepository.deleteAll();
        merkleBatchRepository.deleteAll();
    }

    @Test
    @DisplayName("Should create Merkle batch, link events, and verify inclusion proof")
    void testMerkleBatchCreationAndInclusionProof() {
        // 1. Insert synthetic raw events
        RawEvent r1 = RawEvent.builder()
                .rawEventId("RAW-0001-TEST")
                .rawHashSha256(lineageService.computeSha256("Log payload number 1"))
                .rawMessage("Log payload number 1")
                .ingestionSource("TEST")
                .receivedAt(Instant.now().minusSeconds(60))
                .processingStatus("PROCESSED")
                .build();

        RawEvent r2 = RawEvent.builder()
                .rawEventId("RAW-0002-TEST")
                .rawHashSha256(lineageService.computeSha256("Log payload number 2"))
                .rawMessage("Log payload number 2")
                .ingestionSource("TEST")
                .receivedAt(Instant.now().minusSeconds(30))
                .processingStatus("PROCESSED")
                .build();

        rawEventRepository.save(r1);
        rawEventRepository.save(r2);

        // 2. Trigger Merkle batch
        Optional<MerkleBatch> batchOpt = merkleLedgerService.createBatch();
        assertTrue(batchOpt.isPresent());
        MerkleBatch batch = batchOpt.get();

        assertNotNull(batch.getId());
        assertEquals(2, batch.getEventCount());
        assertNotNull(batch.getMerkleRoot());

        // 3. Verify events updated with batch ID
        RawEvent updatedR1 = rawEventRepository.findByRawEventId("RAW-0001-TEST").orElseThrow();
        assertEquals(batch.getId(), updatedR1.getMerkleBatchId());

        // 4. Verify Inclusion Proof
        MerkleInclusionResult result = lineageService.verifyInclusion("RAW-0001-TEST");
        assertTrue(result.isVerified());
        assertEquals(batch.getId(), result.getMerkleBatchId());
        assertEquals(batch.getMerkleRoot(), result.getMerkleRoot());
        assertEquals(0, result.getLeafIndex());
        assertFalse(result.getProofPath().isEmpty());

        // 5. Test Export Bundle
        Map<String, Object> bundle = merkleLedgerService.exportBatchBundle(batch.getId());
        assertNotNull(bundle);
        assertEquals(batch.getId(), bundle.get("batchId"));
        assertEquals(true, bundle.get("verifiedRootMatchesTree"));
    }
}
