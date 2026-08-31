package com.ulpf.parsers;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ulpf.detection.LogFormat;
import com.ulpf.domain.FieldMapping;
import com.ulpf.domain.ParserEntity;
import com.ulpf.domain.ParserVersion;
import com.ulpf.inference.RegexParserSynthesizer;
import com.ulpf.repository.ParserEntityRepository;
import com.ulpf.repository.ParserVersionRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Component
@RequiredArgsConstructor
@Slf4j
public class DynamicParserRegistry {

    private final List<ParserPlugin> nativeParsers;
    private final ParserEntityRepository parserEntityRepository;
    private final ParserVersionRepository parserVersionRepository;
    private final RegexParserSynthesizer synthesizer;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final Map<String, ParserPlugin> activeRegistry = new ConcurrentHashMap<>();

    @PostConstruct
    public void init() {
        // 1. Register Native Parsers
        for (ParserPlugin plugin : nativeParsers) {
            activeRegistry.put(plugin.getName(), plugin);
            log.info("Registered Native Parser: {} (v{})", plugin.getName(), plugin.getVersion());
        }

        // 2. Load and synthesize Approved Dynamic Parsers from DB
        try {
            List<ParserEntity> dynamicEntities = parserEntityRepository.findAll();
            for (ParserEntity entity : dynamicEntities) {
                if (!"DYNAMIC_INFERRED".equalsIgnoreCase(entity.getParserType())) {
                    continue;
                }
                Optional<ParserVersion> activeVersionOpt = parserVersionRepository.findByParserIdAndActiveTrue(entity.getId());
                if (activeVersionOpt.isPresent() && entity.isActive()) {
                    ParserVersion pv = activeVersionOpt.get();
                    List<FieldMapping> mappings = Collections.emptyList();
                    if (pv.getFieldMappingJson() != null && !pv.getFieldMappingJson().isBlank()) {
                        mappings = objectMapper.readValue(pv.getFieldMappingJson(), new TypeReference<List<FieldMapping>>() {});
                    }
                    DynamicGeneratedParser dynamicParser = synthesizer.synthesize(
                            entity.getName(),
                            entity.getDisplayName(),
                            pv.getVersion(),
                            entity.getFormatType(),
                            pv.getTemplatePattern(),
                            pv.getRegexPattern(),
                            mappings,
                            pv.getAverageConfidence() != null ? pv.getAverageConfidence() : 0.90
                    );
                    activeRegistry.put(entity.getName(), dynamicParser);
                    log.info("Loaded Dynamic Inferred Parser from DB: {} (v{})", entity.getName(), pv.getVersion());
                }
            }
        } catch (Exception e) {
            log.warn("Could not load dynamic parsers from DB during startup: {}", e.getMessage());
        }
    }

    /**
     * Hot-register an approved dynamic parser immediately without restarting.
     */
    public void registerApprovedParser(DynamicGeneratedParser parser) {
        activeRegistry.put(parser.getName(), parser);
        log.info("HOT-REGISTERED approved parser: {} (v{}) - live immediately!", parser.getName(), parser.getVersion());
    }

    /**
     * Get all active parser plugins (Native + Dynamic)
     */
    public Collection<ParserPlugin> getActiveParsers() {
        return Collections.unmodifiableCollection(activeRegistry.values());
    }

    /**
     * Get a specific parser by name
     */
    public Optional<ParserPlugin> getParser(String name) {
        return Optional.ofNullable(activeRegistry.get(name));
    }

    /**
     * Toggle parser active state
     */
    public boolean toggleParser(String name, boolean active) {
        ParserPlugin p = activeRegistry.get(name);
        if (p != null) {
            p.setActive(active);
            return true;
        }
        return false;
    }

    /**
     * Find best candidate parser for a raw log payload and detected format.
     */
    public Optional<ParserPlugin> findMatchingParser(String rawMessage, LogFormat format) {
        // First check if any dynamic parser matches specifically
        for (ParserPlugin parser : activeRegistry.values()) {
            if (parser instanceof DynamicGeneratedParser && parser.isActive() && parser.canParse(rawMessage, format)) {
                return Optional.of(parser);
            }
        }

        // Next check native parsers
        for (ParserPlugin parser : activeRegistry.values()) {
            if (parser.isActive() && parser.canParse(rawMessage, format)) {
                return Optional.of(parser);
            }
        }

        return Optional.empty();
    }
}
