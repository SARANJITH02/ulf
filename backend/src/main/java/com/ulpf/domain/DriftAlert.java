package com.ulpf.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "drift_alerts", indexes = {
    @Index(name = "idx_drift_parser", columnList = "parserName"),
    @Index(name = "idx_drift_status", columnList = "status"),
    @Index(name = "idx_drift_detected_at", columnList = "detectedAt")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DriftAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 64)
    private String parserName;

    @Column(length = 32)
    private String parserVersion;

    @Column(nullable = false)
    private Double baselineConfidence;

    @Column(nullable = false)
    private Double currentConfidence;

    private Double confidenceDrop;

    private Double successRate;

    private int totalEvents;

    private int dlqEvents;

    @Column(nullable = false, length = 32)
    private String status; // OPEN, ACKNOWLEDGED

    @Column(nullable = false)
    private Instant detectedAt;

    private Instant acknowledgedAt;

    @Column(length = 64)
    private String acknowledgedBy;

    @Lob
    @Column(columnDefinition = "TEXT")
    private String details;
}
