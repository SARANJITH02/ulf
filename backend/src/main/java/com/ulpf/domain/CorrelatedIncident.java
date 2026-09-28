package com.ulpf.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "correlated_incidents", indexes = {
        @Index(name = "idx_incident_corr_key", columnList = "correlationKey"),
        @Index(name = "idx_incident_status", columnList = "status"),
        @Index(name = "idx_incident_last_seen", columnList = "lastSeenAt")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CorrelatedIncident {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 64)
    private String incidentKey;

    @Column(nullable = false, length = 128)
    private String correlationKey;

    @Column(nullable = false, length = 32)
    private String keyType; // "IP" or "USER"

    @Column(nullable = false, length = 64)
    private String rootEventId; // Earliest timestamped event in group (heuristic hypothesis)

    @Lob
    @Column(columnDefinition = "TEXT")
    private String memberEventIds; // JSON array of event IDs

    @Lob
    @Column(columnDefinition = "TEXT")
    private String tacticChain; // JSON array of tactics in MITRE kill-chain order

    @Lob
    @Column(columnDefinition = "TEXT")
    private String narrativeText; // Structured template narrative

    @Column(nullable = false, length = 32)
    private String severity; // "CRITICAL", "HIGH", "MEDIUM", "LOW"

    @Column(nullable = false, length = 32)
    @Builder.Default
    private String status = "OPEN"; // "OPEN", "INVESTIGATING", "CLOSED"

    @Column(nullable = false)
    @Builder.Default
    private Integer distinctTacticCount = 0;

    @Column(nullable = false)
    @Builder.Default
    private Integer eventCount = 0;

    @Column(nullable = false)
    private Instant firstSeenAt;

    @Column(nullable = false)
    private Instant lastSeenAt;

    @Column(nullable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    @Builder.Default
    private Instant updatedAt = Instant.now();
}
