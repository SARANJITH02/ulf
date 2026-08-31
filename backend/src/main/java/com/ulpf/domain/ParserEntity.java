package com.ulpf.domain;

import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "parsers", indexes = {
    @Index(name = "idx_parser_name", columnList = "name")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ParserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 64)
    private String name; // e.g. cisco_asa_syslog, custom_inferred_fw

    @Column(length = 64)
    private String displayName;

    @Column(nullable = false, length = 32)
    private String parserType; // NATIVE, DYNAMIC_INFERRED

    @Column(nullable = false, length = 32)
    private String formatType; // SYSLOG, CEF, LEEF, JSON, CSV, UNKNOWN

    @Column(nullable = false)
    private boolean active;

    @Column(length = 512)
    private String description;

    @Column(nullable = false, length = 32)
    private String currentVersion; // e.g. 1.0

    @OneToMany(mappedBy = "parser", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @Builder.Default
    private List<ParserVersion> versions = new ArrayList<>();

    @Column(nullable = false)
    private Instant createdAt;

    private Instant updatedAt;

    @Column(length = 64)
    private String createdBy;
}
