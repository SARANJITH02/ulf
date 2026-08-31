package com.ulpf.enrichment;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ulpf.normalization.OcsfSchema;
import jakarta.annotation.PostConstruct;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Service
@Slf4j
public class MitreMapper {

    private final List<MitreRule> rules = new ArrayList<>();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class MitreRule {
        private String id;
        private String name;
        private String conditionType;
        private List<Integer> destinationPorts;
        private List<String> actions;
        private List<String> keywords;
        private String techniqueId;
        private String techniqueName;
        private String tactic;
        private String category;
        private int riskScore;
    }

    @PostConstruct
    public void init() {
        try {
            ClassPathResource resource = new ClassPathResource("mitre_rules.json");
            if (resource.exists()) {
                try (InputStream is = resource.getInputStream()) {
                    List<MitreRule> loaded = objectMapper.readValue(is, new TypeReference<List<MitreRule>>() {});
                    rules.addAll(loaded);
                    log.info("Loaded {} offline MITRE ATT&CK heuristic rules", rules.size());
                }
            }
        } catch (Exception e) {
            log.warn("Failed loading mitre_rules.json: {}", e.getMessage());
        }
    }

    public OcsfSchema.ThreatDetail evaluateThreat(OcsfSchema event) {
        if (event == null) return null;

        Integer dstPort = event.getDestination() != null ? event.getDestination().getPort() : null;
        String action = event.getEvent() != null ? event.getEvent().getAction() : null;
        String rawMsg = event.getRaw() != null ? event.getRaw().getMessage() : "";

        for (MitreRule rule : rules) {
            boolean portMatch = rule.getDestinationPorts() == null ||
                    (dstPort != null && rule.getDestinationPorts().contains(dstPort));

            boolean actionMatch = rule.getActions() == null ||
                    (action != null && rule.getActions().stream().anyMatch(a -> action.toLowerCase().contains(a.toLowerCase())));

            boolean keywordMatch = rule.getKeywords() == null ||
                    (rawMsg != null && rule.getKeywords().stream().anyMatch(k -> rawMsg.toLowerCase().contains(k.toLowerCase())));

            if ("PORT_ACTION".equalsIgnoreCase(rule.getConditionType())) {
                if (portMatch && actionMatch) {
                    return buildThreatDetail(rule);
                }
            } else if ("KEYWORD_OR_PORT".equalsIgnoreCase(rule.getConditionType())) {
                if (portMatch || keywordMatch) {
                    return buildThreatDetail(rule);
                }
            } else if ("SUSPICIOUS_PORT".equalsIgnoreCase(rule.getConditionType()) || "PORT".equalsIgnoreCase(rule.getConditionType())) {
                if (portMatch && dstPort != null) {
                    return buildThreatDetail(rule);
                }
            }
        }

        return null;
    }

    private OcsfSchema.ThreatDetail buildThreatDetail(MitreRule rule) {
        return OcsfSchema.ThreatDetail.builder()
                .mitreTechniqueId(rule.getTechniqueId())
                .mitreTechniqueName(rule.getTechniqueName())
                .mitreTactic(rule.getTactic())
                .category(rule.getCategory())
                .riskScore(rule.getRiskScore())
                .build();
    }
}
