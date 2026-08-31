package com.ulpf.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

@Entity
@Table(name = "parser_versions", indexes = {
    @Index(name = "idx_pv_parser_id", columnList = "parser_id"),
    @Index(name = "idx_pv_version", columnList = "version")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ParserVersion {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parser_id", nullable = false)
    @JsonIgnore
    private ParserEntity parser;

    @Column(nullable = false, length = 32)
    private String version; // e.g. 1.0, 1.1

    @Lob
    @Column(columnDefinition = "TEXT")
    private String regexPattern;

    @Lob
    @Column(columnDefinition = "TEXT")
    private String templatePattern;

    @Lob
    @Column(columnDefinition = "TEXT")
    private String fieldMappingJson; // JSON representation of FieldMapping items

    @Column(nullable = false)
    private boolean active;

    private Double averageConfidence;

    @Column(length = 64)
    private String approvedBy;

    private Instant approvedAt;

    @Column(nullable = false)
    private Instant createdAt;

    @Lob
    @Column(columnDefinition = "TEXT")
    private String sampleLog;
}
