package com.ulpf.domain;

import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

@Entity
@Table(name = "raw_events", indexes = {
    @Index(name = "idx_raw_hash", columnList = "rawHashSha256"),
    @Index(name = "idx_raw_event_id", columnList = "rawEventId"),
    @Index(name = "idx_raw_received_at", columnList = "receivedAt")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RawEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 64)
    private String rawEventId; // e.g. RAW-e3b0c44298fc1c14

    @Column(nullable = false, length = 64)
    private String rawHashSha256;

    @Lob
    @Column(nullable = false, columnDefinition = "TEXT")
    private String rawMessage;

    @Column(nullable = false, length = 32)
    private String ingestionSource; // UDP, TCP, REST_SINGLE, REST_BULK

    @Column(nullable = false)
    private Instant receivedAt;

    @Column(length = 32)
    private String detectedFormat; // SYSLOG, CEF, LEEF, JSON, CSV, UNKNOWN

    @Column(length = 32)
    private String processingStatus; // PROCESSED, DLQ, PENDING
}
