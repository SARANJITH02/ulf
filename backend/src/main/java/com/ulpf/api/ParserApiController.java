package com.ulpf.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ulpf.domain.FieldMapping;
import com.ulpf.domain.ParserEntity;
import com.ulpf.domain.ParserVersion;
import com.ulpf.inference.RegexParserSynthesizer;
import com.ulpf.parsers.DynamicGeneratedParser;
import com.ulpf.parsers.DynamicParserRegistry;
import com.ulpf.parsers.ParserPlugin;
import com.ulpf.repository.ParserEntityRepository;
import com.ulpf.repository.ParserVersionRepository;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.*;

@RestController
@RequestMapping("/api/v1/parsers")
@RequiredArgsConstructor
@Slf4j
public class ParserApiController {

    private final DynamicParserRegistry parserRegistry;
    private final ParserEntityRepository parserEntityRepository;
    private final ParserVersionRepository parserVersionRepository;
    private final RegexParserSynthesizer synthesizer;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ParserApprovalRequest {
        private String parserName;
        private String displayName;
        private String version;
        private String formatType;
        private String description;
        private String templatePattern;
        private String regexPattern;
        private List<FieldMapping> fieldMappings;
        private Double averageConfidence;
        private String sampleLog;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ParserSummaryDto {
        private String name;
        private String displayName;
        private String version;
        private String formatType;
        private String parserType; // NATIVE or DYNAMIC_INFERRED
        private boolean active;
        private Double confidence;
        private String templatePattern;
    }

    @PostMapping("/approve")
    @Transactional
    public ResponseEntity<?> approveAndRegisterParser(@RequestBody ParserApprovalRequest request,
                                                      Authentication authentication) {
        String operator = authentication != null ? authentication.getName() : "OPERATOR_APPROVED";
        log.info("OPERATOR APPROVAL received from '{}' for parser: {}", operator, request.getParserName());

        if (request.getParserName() == null || request.getParserName().isBlank() ||
            request.getRegexPattern() == null || request.getRegexPattern().isBlank()) {
            return ResponseEntity.badRequest().body("Parser name and regex pattern are required for approval");
        }

        String version = request.getVersion() != null ? request.getVersion() : "1.0";
        String formatType = request.getFormatType() != null ? request.getFormatType() : "CUSTOM";
        double confidence = request.getAverageConfidence() != null ? request.getAverageConfidence() : 0.95;

        // 1. Synthesize live runnable DynamicGeneratedParser
        DynamicGeneratedParser dynamicParser = synthesizer.synthesize(
                request.getParserName(),
                request.getDisplayName() != null ? request.getDisplayName() : request.getParserName(),
                version,
                formatType,
                request.getTemplatePattern(),
                request.getRegexPattern(),
                request.getFieldMappings() != null ? request.getFieldMappings() : Collections.emptyList(),
                confidence
        );

        // 2. Persist in Database (ParserEntity and ParserVersion)
        ParserEntity entity = parserEntityRepository.findByName(request.getParserName())
                .orElseGet(() -> ParserEntity.builder()
                        .name(request.getParserName())
                        .displayName(request.getDisplayName() != null ? request.getDisplayName() : request.getParserName())
                        .parserType("DYNAMIC_INFERRED")
                        .formatType(formatType)
                        .active(true)
                        .description(request.getDescription())
                        .currentVersion(version)
                        .createdAt(Instant.now())
                        .createdBy(operator)
                        .build());

        entity.setActive(true);
        entity.setCurrentVersion(version);
        entity.setUpdatedAt(Instant.now());
        entity = parserEntityRepository.save(entity);

        String mappingJson;
        try {
            mappingJson = objectMapper.writeValueAsString(request.getFieldMappings());
        } catch (JsonProcessingException e) {
            mappingJson = "[]";
        }

        ParserVersion pv = ParserVersion.builder()
                .parser(entity)
                .version(version)
                .regexPattern(request.getRegexPattern())
                .templatePattern(request.getTemplatePattern())
                .fieldMappingJson(mappingJson)
                .active(true)
                .averageConfidence(confidence)
                .approvedBy(operator)
                .approvedAt(Instant.now())
                .createdAt(Instant.now())
                .sampleLog(request.getSampleLog())
                .build();

        parserVersionRepository.save(pv);

        // 3. Hot-Register in In-Memory Registry (Zero Restart!)
        parserRegistry.registerApprovedParser(dynamicParser);

        return ResponseEntity.ok(Map.of(
                "status", "APPROVED_AND_REGISTERED",
                "parserName", request.getParserName(),
                "version", version,
                "approvedBy", operator,
                "liveImmediately", true
        ));
    }

    @GetMapping
    public ResponseEntity<List<ParserSummaryDto>> listParsers() {
        List<ParserSummaryDto> list = new ArrayList<>();
        for (ParserPlugin p : parserRegistry.getActiveParsers()) {
            String type = (p instanceof DynamicGeneratedParser) ? "DYNAMIC_INFERRED" : "NATIVE";
            Double conf = (p instanceof DynamicGeneratedParser d) ? d.getConfidenceScore() : 0.99;
            String template = (p instanceof DynamicGeneratedParser d) ? d.getTemplatePattern() : null;

            list.add(ParserSummaryDto.builder()
                    .name(p.getName())
                    .displayName(p.getDisplayName())
                    .version(p.getVersion())
                    .formatType(p.getFormatType())
                    .parserType(type)
                    .active(p.isActive())
                    .confidence(conf)
                    .templatePattern(template)
                    .build());
        }
        return ResponseEntity.ok(list);
    }

    @PostMapping("/{name}/toggle")
    public ResponseEntity<?> toggleParser(@PathVariable String name, @RequestParam boolean active) {
        boolean toggled = parserRegistry.toggleParser(name, active);
        parserEntityRepository.findByName(name).ifPresent(e -> {
            e.setActive(active);
            parserEntityRepository.save(e);
        });

        if (toggled) {
            return ResponseEntity.ok(Map.of("parser", name, "active", active));
        }
        return ResponseEntity.notFound().build();
    }
}
