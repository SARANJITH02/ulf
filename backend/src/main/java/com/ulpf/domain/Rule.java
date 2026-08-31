package com.ulpf.domain;

import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

@Entity
@Table(name = "rules", indexes = {
    @Index(name = "idx_rule_key", columnList = "ruleKey")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Rule {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 64)
    private String ruleKey; // e.g. CONFIDENCE_HIGH_THRESHOLD, ENRICHMENT_RFC1918_ENABLED

    @Column(nullable = false, length = 128)
    private String ruleName;

    @Column(nullable = false, length = 64)
    private String ruleCategory; // THRESHOLD, ENRICHMENT, DLQ_POLICY, APPROVAL_POLICY

    @Column(nullable = false, length = 512)
    private String ruleValue; // "0.90", "true", "3"

    @Column(length = 512)
    private String description;

    @Column(nullable = false)
    private boolean enabled;

    @Column(nullable = false)
    private Instant updatedAt;

    @Column(length = 64)
    private String updatedBy;
}
