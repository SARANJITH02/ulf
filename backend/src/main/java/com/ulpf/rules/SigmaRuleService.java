package com.ulpf.rules;

import com.ulpf.domain.SigmaMatch;
import com.ulpf.domain.SigmaRule;
import com.ulpf.metrics.MetricsBroadcaster;
import com.ulpf.normalization.OcsfSchema;
import com.ulpf.repository.SigmaMatchRepository;
import com.ulpf.repository.SigmaRuleRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
@Slf4j
public class SigmaRuleService {

    private final SigmaRuleRepository sigmaRuleRepository;
    private final SigmaMatchRepository sigmaMatchRepository;
    private final SigmaRuleParser ruleParser;
    private final SigmaRuleEvaluator ruleEvaluator;
    private final MetricsBroadcaster metricsBroadcaster;

    private final Map<String, SigmaRuleParser.ParsedSigmaRule> activeParsedRules = new ConcurrentHashMap<>();

    @PostConstruct
    public void init() {
        loadStarterRules();
        refreshActiveRulesCache();
    }

    /**
     * Load bundled starter Sigma YAML rules if not already present in the database.
     */
    @Transactional
    public void loadStarterRules() {
        try {
            PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
            Resource[] resources = resolver.getResources("classpath:sigma_rules/*.yml");

            for (Resource res : resources) {
                try (InputStream is = res.getInputStream()) {
                    String yamlText = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                    SigmaRuleParser.ParsedSigmaRule parsed = ruleParser.parse(yamlText);

                    if (!sigmaRuleRepository.existsById(parsed.getId())) {
                        SigmaRule entity = SigmaRule.builder()
                                .id(parsed.getId())
                                .title(parsed.getTitle())
                                .description(parsed.getDescription())
                                .sigmaYaml(yamlText)
                                .logsourceCategory(parsed.getCategory())
                                .logsourceProduct(parsed.getProduct())
                                .severity(parsed.getSeverity())
                                .techniqueId(parsed.getTechniqueId())
                                .tactic(parsed.getTactic())
                                .enabled(true)
                                .createdBy("SYSTEM_STARTER_PACK")
                                .createdAt(Instant.now())
                                .build();
                        sigmaRuleRepository.save(entity);
                        log.info("Loaded starter Sigma rule: {} [{}]", entity.getTitle(), entity.getId());
                    }
                } catch (Exception e) {
                    log.warn("Failed to load starter Sigma rule from {}: {}", res.getFilename(), e.getMessage());
                }
            }
        } catch (Exception e) {
            log.warn("Could not scan starter Sigma rules directory: {}", e.getMessage());
        }
    }

    /**
     * Refresh in-memory parsed rules cache for fast evaluation on live event stream.
     */
    public void refreshActiveRulesCache() {
        activeParsedRules.clear();
        List<SigmaRule> enabledEntities = sigmaRuleRepository.findByEnabledTrue();
        for (SigmaRule entity : enabledEntities) {
            try {
                SigmaRuleParser.ParsedSigmaRule parsed = ruleParser.parse(entity.getSigmaYaml());
                activeParsedRules.put(entity.getId(), parsed);
            } catch (Exception e) {
                log.error("Could not compile active Sigma rule {}: {}", entity.getId(), e.getMessage());
            }
        }
        log.info("Compiled {} active Sigma rules in memory", activeParsedRules.size());
    }

    /**
     * Evaluate all active Sigma rules against a normalized OCSF event.
     */
    public List<OcsfSchema.SigmaMatchSummary> evaluate(OcsfSchema ocsf) {
        if (ocsf == null || activeParsedRules.isEmpty()) {
            return Collections.emptyList();
        }

        List<OcsfSchema.SigmaMatchSummary> matches = new ArrayList<>();
        for (SigmaRuleParser.ParsedSigmaRule rule : activeParsedRules.values()) {
            try {
                Optional<OcsfSchema.SigmaMatchSummary> matchOpt = ruleEvaluator.evaluateRule(rule, ocsf);
                matchOpt.ifPresent(matches::add);
            } catch (Exception e) {
                log.trace("Error evaluating rule {} against event: {}", rule.getId(), e.getMessage());
            }
        }
        return matches;
    }

    /**
     * Persist matches in database and broadcast alerts over WebSocket /topic/alerts.
     */
    @Transactional
    public void recordMatches(OcsfSchema ocsf, List<OcsfSchema.SigmaMatchSummary> matches) {
        if (matches == null || matches.isEmpty() || ocsf == null) return;

        for (OcsfSchema.SigmaMatchSummary summary : matches) {
            String srcIp = ocsf.getSource() != null ? ocsf.getSource().getIp() : null;
            String dstIp = ocsf.getDestination() != null ? ocsf.getDestination().getIp() : null;
            Integer dstPort = ocsf.getDestination() != null ? ocsf.getDestination().getPort() : null;

            SigmaMatch matchEntity = SigmaMatch.builder()
                    .eventId(ocsf.getEventId())
                    .rawEventId(ocsf.getRawEventId())
                    .ruleId(summary.getRuleId())
                    .ruleTitle(summary.getRuleTitle())
                    .severity(summary.getSeverity())
                    .techniqueId(summary.getTechniqueId())
                    .tactic(summary.getTactic())
                    .sourceIp(srcIp)
                    .destinationIp(dstIp)
                    .destinationPort(dstPort)
                    .details(summary.getMatchedDetails())
                    .matchedAt(Instant.now())
                    .build();

            sigmaMatchRepository.save(matchEntity);

            // Broadcast match over /topic/alerts
            Map<String, Object> alertPayload = new LinkedHashMap<>();
            alertPayload.put("alertType", "SIGMA_DETECTION");
            alertPayload.put("id", matchEntity.getId());
            alertPayload.put("eventId", matchEntity.getEventId());
            alertPayload.put("rawEventId", matchEntity.getRawEventId());
            alertPayload.put("ruleId", matchEntity.getRuleId());
            alertPayload.put("title", matchEntity.getRuleTitle());
            alertPayload.put("severity", matchEntity.getSeverity());
            alertPayload.put("techniqueId", matchEntity.getTechniqueId());
            alertPayload.put("tactic", matchEntity.getTactic());
            alertPayload.put("sourceIp", srcIp);
            alertPayload.put("destinationIp", dstIp);
            alertPayload.put("destinationPort", dstPort);
            alertPayload.put("matchedAt", matchEntity.getMatchedAt().toString());

            metricsBroadcaster.broadcastAlert(alertPayload);
        }
    }

    @Transactional
    public SigmaRule createOrUpdateRule(String yamlText, String user) {
        SigmaRuleParser.ParsedSigmaRule parsed = ruleParser.parse(yamlText);

        Optional<SigmaRule> existingOpt = sigmaRuleRepository.findById(parsed.getId());
        SigmaRule rule;

        if (existingOpt.isPresent()) {
            rule = existingOpt.get();
            rule.setTitle(parsed.getTitle());
            rule.setDescription(parsed.getDescription());
            rule.setSigmaYaml(yamlText);
            rule.setLogsourceCategory(parsed.getCategory());
            rule.setLogsourceProduct(parsed.getProduct());
            rule.setSeverity(parsed.getSeverity());
            rule.setTechniqueId(parsed.getTechniqueId());
            rule.setTactic(parsed.getTactic());
            rule.setUpdatedAt(Instant.now());
        } else {
            rule = SigmaRule.builder()
                    .id(parsed.getId())
                    .title(parsed.getTitle())
                    .description(parsed.getDescription())
                    .sigmaYaml(yamlText)
                    .logsourceCategory(parsed.getCategory())
                    .logsourceProduct(parsed.getProduct())
                    .severity(parsed.getSeverity())
                    .techniqueId(parsed.getTechniqueId())
                    .tactic(parsed.getTactic())
                    .enabled(true)
                    .createdBy(user != null ? user : "OPERATOR")
                    .createdAt(Instant.now())
                    .build();
        }

        SigmaRule saved = sigmaRuleRepository.save(rule);
        refreshActiveRulesCache();
        return saved;
    }

    @Transactional
    public Optional<SigmaRule> toggleRule(String id, boolean enabled) {
        Optional<SigmaRule> ruleOpt = sigmaRuleRepository.findById(id);
        if (ruleOpt.isPresent()) {
            SigmaRule rule = ruleOpt.get();
            rule.setEnabled(enabled);
            rule.setUpdatedAt(Instant.now());
            sigmaRuleRepository.save(rule);
            refreshActiveRulesCache();
            return Optional.of(rule);
        }
        return Optional.empty();
    }

    @Transactional
    public boolean deleteRule(String id) {
        if (sigmaRuleRepository.existsById(id)) {
            sigmaRuleRepository.deleteById(id);
            refreshActiveRulesCache();
            return true;
        }
        return false;
    }

    public List<SigmaRule> listAllRules() {
        return sigmaRuleRepository.findAllByOrderByCreatedAtDesc();
    }

    public Optional<SigmaRule> getRuleById(String id) {
        return sigmaRuleRepository.findById(id);
    }
}
