package com.ulpf.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "sigma_matches", indexes = {
    @Index(name = "idx_sigma_match_event", columnList = "eventId"),
    @Index(name = "idx_sigma_match_rule", columnList = "ruleId"),
    @Index(name = "idx_sigma_match_time", columnList = "matchedAt"),
    @Index(name = "idx_sigma_match_sev", columnList = "severity")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SigmaMatch {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 64)
    private String eventId;

    @Column(length = 64)
    private String rawEventId;

    @Column(nullable = false, length = 64)
    private String ruleId;

    @Column(nullable = false, length = 255)
    private String ruleTitle;

    @Column(nullable = false, length = 32)
    private String severity;

    @Column(length = 32)
    private String techniqueId;

    @Column(length = 64)
    private String tactic;

    @Column(length = 64)
    private String sourceIp;

    @Column(length = 64)
    private String destinationIp;

    private Integer destinationPort;

    @Lob
    @Column(columnDefinition = "TEXT")
    private String details;

    @Column(nullable = false)
    private Instant matchedAt;
}
