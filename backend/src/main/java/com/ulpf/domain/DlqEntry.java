package com.ulpf.domain;

import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

@Entity
@Table(name = "dlq_entries", indexes = {
    @Index(name = "idx_dlq_raw_event_id", columnList = "rawEventId"),
    @Index(name = "idx_dlq_status", columnList = "status"),
    @Index(name = "idx_dlq_created_at", columnList = "createdAt")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DlqEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 64)
    private String rawEventId;

    @Lob
    @Column(nullable = false, columnDefinition = "TEXT")
    private String rawMessage;

    @Column(length = 64)
    private String failureCode; // UNPARSEABLE_FORMAT, LOW_CONFIDENCE, VALIDATION_FAILED, REJECTED_BY_OPERATOR

    @Column(length = 512)
    private String failureReason;

    @Column(length = 32)
    private String detectedFormat;

    private Integer retryCount;

    @Column(nullable = false, length = 32)
    private String status; // NEW, RETRIED, RESOLVED, DISCARDED

    @Column(nullable = false)
    private Instant createdAt;

    private Instant updatedAt;
}
