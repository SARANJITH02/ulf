package com.ulpf.api;

import com.ulpf.domain.MerkleBatch;
import com.ulpf.lineage.CryptographicLineageService;
import com.ulpf.lineage.MerkleInclusionResult;
import com.ulpf.lineage.MerkleLedgerService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
@Slf4j
public class AuditApiController {

    private final MerkleLedgerService merkleLedgerService;
    private final CryptographicLineageService lineageService;

    @GetMapping("/audit/merkle-batches")
    public ResponseEntity<List<MerkleBatch>> listMerkleBatches() {
        return ResponseEntity.ok(merkleLedgerService.listAllBatches());
    }

    @GetMapping("/audit/merkle-batches/{id}")
    public ResponseEntity<?> getMerkleBatch(@PathVariable String id) {
        Optional<MerkleBatch> batchOpt = merkleLedgerService.getBatchById(id);
        if (batchOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(batchOpt.get());
    }

    @GetMapping("/audit/merkle-batches/{id}/export")
    public ResponseEntity<Map<String, Object>> exportMerkleBatch(@PathVariable String id) {
        try {
            Map<String, Object> exportBundle = merkleLedgerService.exportBatchBundle(id);
            return ResponseEntity.ok(exportBundle);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.notFound().build();
        }
    }

    @PostMapping("/audit/merkle-batches/trigger")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> triggerMerkleBatch() {
        Optional<MerkleBatch> created = merkleLedgerService.createBatch();
        if (created.isEmpty()) {
            return ResponseEntity.ok(Map.of(
                    "status", "NO_EVENTS",
                    "message", "No unbatched raw events available to create a Merkle batch"
            ));
        }
        return ResponseEntity.ok(created.get());
    }

    @GetMapping("/events/{id}/verify-inclusion")
    public ResponseEntity<MerkleInclusionResult> verifyInclusion(@PathVariable String id) {
        MerkleInclusionResult result = lineageService.verifyInclusion(id);
        return ResponseEntity.ok(result);
    }
}
