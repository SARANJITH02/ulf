package com.ulpf.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "merkle_batches", indexes = {
    @Index(name = "idx_merkle_batch_id", columnList = "id"),
    @Index(name = "idx_merkle_root", columnList = "merkleRoot"),
    @Index(name = "idx_merkle_created_at", columnList = "createdAt")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MerkleBatch {

    @Id
    @Column(nullable = false, length = 64)
    private String id; // e.g. BATCH-UUID

    @Column(name = "batch_number")
    private Long batchNumber;

    @Column(nullable = false)
    private Instant periodStart;

    @Column(nullable = false)
    private Instant periodEnd;

    @Column(nullable = false)
    private int eventCount;

    @Column(nullable = false, length = 64)
    private String merkleRoot;

    @Lob
    @Column(nullable = false, columnDefinition = "TEXT")
    private String leafOrderEventIds; // JSON representation of leaf event IDs and hashes in deterministic order

    @Column(nullable = false)
    private Instant createdAt;
}
