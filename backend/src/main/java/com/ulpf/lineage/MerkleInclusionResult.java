package com.ulpf.lineage;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MerkleInclusionResult {
    private String eventId;
    private String rawEventId;
    private String rawHashSha256;
    private String merkleBatchId;
    private String merkleRoot;
    private Integer leafIndex;
    private Integer totalLeaves;
    private List<MerkleTree.ProofNode> proofPath;
    private boolean verified;
    private Instant batchedAt;
    private Instant verifiedAt;
    private String statusMessage;
}
