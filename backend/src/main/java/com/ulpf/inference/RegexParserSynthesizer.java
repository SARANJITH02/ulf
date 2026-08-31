package com.ulpf.inference;

import com.ulpf.domain.FieldMapping;
import com.ulpf.parsers.DynamicGeneratedParser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@Slf4j
public class RegexParserSynthesizer {

    public DynamicGeneratedParser synthesize(String parserName,
                                             String displayName,
                                             String version,
                                             String formatType,
                                             String templatePattern,
                                             String regexPattern,
                                             List<FieldMapping> fieldMappings,
                                             double confidenceScore) {
        log.info("Synthesizing dynamic parser: {} (v{}) with {} mapped slots", parserName, version, fieldMappings.size());
        return new DynamicGeneratedParser(
                parserName,
                displayName,
                version,
                formatType,
                templatePattern,
                regexPattern,
                fieldMappings,
                confidenceScore
        );
    }
}
