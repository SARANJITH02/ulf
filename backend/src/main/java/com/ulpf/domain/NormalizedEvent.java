package com.ulpf.domain;

import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

@Entity
@Table(name = "normalized_events", indexes = {
    @Index(name = "idx_norm_event_id", columnList = "eventId"),
    @Index(name = "idx_norm_raw_event_id", columnList = "rawEventId"),
    @Index(name = "idx_norm_timestamp", columnList = "timestampUtc"),
    @Index(name = "idx_norm_source_ip", columnList = "sourceIp"),
    @Index(name = "idx_norm_dest_ip", columnList = "destinationIp"),
    @Index(name = "idx_norm_action", columnList = "action"),
    @Index(name = "idx_norm_severity", columnList = "severity")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class NormalizedEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 64)
    private String eventId; // e.g. ULPF-550e8400-e29b-41d4-a716-446655440000

    @Column(nullable = false, length = 64)
    private String rawEventId;

    @Column(nullable = false, length = 64)
    private String rawHashSha256;

    @Column(nullable = false)
    private Instant timestampUtc;

    @Column(length = 64)
    private String category;

    @Column(length = 64)
    private String eventType;

    @Column(length = 64)
    private String action;

    @Column(length = 32)
    private String severity;

    @Column(length = 64)
    private String sourceIp;

    private Integer sourcePort;

    @Column(length = 64)
    private String destinationIp;

    private Integer destinationPort;

    @Column(length = 32)
    private String protocol;

    @Column(length = 64)
    private String observerVendor;

    @Column(length = 64)
    private String observerProduct;

    @Column(length = 64)
    private String parserName;

    @Column(length = 32)
    private String parserVersion;

    private Double averageConfidence;

    @Column(length = 32)
    private String format;

    @Lob
    @Column(nullable = false, columnDefinition = "TEXT")
    private String ocsfJson;

    @Column(nullable = false)
    private Instant processedAt;
}
