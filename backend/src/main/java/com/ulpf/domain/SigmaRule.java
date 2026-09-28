package com.ulpf.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "sigma_rules", indexes = {
    @Index(name = "idx_sigma_rule_id", columnList = "id"),
    @Index(name = "idx_sigma_severity", columnList = "severity"),
    @Index(name = "idx_sigma_enabled", columnList = "enabled")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SigmaRule {

    @Id
    @Column(nullable = false, length = 64)
    private String id; // e.g. SIGMA-SSH-BRUTEFORCE-001

    @Column(nullable = false, length = 255)
    private String title;

    @Column(length = 512)
    private String description;

    @Lob
    @Column(nullable = false, columnDefinition = "TEXT")
    private String sigmaYaml; // Raw source of truth

    @Column(length = 64)
    private String logsourceCategory; // e.g. firewall, network_traffic

    @Column(length = 64)
    private String logsourceProduct;

    @Column(nullable = false, length = 32)
    private String severity; // critical, high, medium, low, informational

    @Column(length = 32)
    private String techniqueId; // e.g. T1110

    @Column(length = 64)
    private String tactic; // e.g. Credential Access

    @Column(nullable = false)
    private boolean enabled;

    @Column(length = 64)
    private String createdBy;

    @Column(nullable = false)
    private Instant createdAt;

    private Instant updatedAt;
}
