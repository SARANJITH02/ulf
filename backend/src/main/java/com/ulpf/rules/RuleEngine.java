package com.ulpf.rules;

import com.ulpf.domain.Rule;
import com.ulpf.repository.RuleRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
@Slf4j
public class RuleEngine {

    private final RuleRepository ruleRepository;

    private final Map<String, String> runtimeRuleCache = new ConcurrentHashMap<>();

    public static final String KEY_CONFIDENCE_HIGH = "CONFIDENCE_HIGH_THRESHOLD";
    public static final String KEY_CONFIDENCE_MED = "CONFIDENCE_MEDIUM_THRESHOLD";
    public static final String KEY_ENRICH_RFC1918 = "ENRICHMENT_RFC1918_ENABLED";
    public static final String KEY_ENRICH_MITRE = "ENRICHMENT_MITRE_ENABLED";
    public static final String KEY_DLQ_MAX_RETRIES = "DLQ_MAX_RETRIES";
    public static final String KEY_REQUIRE_APPROVAL = "REQUIRE_OPERATOR_APPROVAL";

    @PostConstruct
    public void init() {
        seedDefaultRule(KEY_CONFIDENCE_HIGH, "High Confidence Cutoff", "THRESHOLD", "0.90", "Cutoff for high-confidence inferred parser mapping", true);
        seedDefaultRule(KEY_CONFIDENCE_MED, "Medium Confidence Cutoff", "THRESHOLD", "0.70", "Cutoff for medium vs low confidence routing", true);
        seedDefaultRule(KEY_ENRICH_RFC1918, "RFC1918 IP Classification", "ENRICHMENT", "true", "Classify source/destination IP as internal or public", true);
        seedDefaultRule(KEY_ENRICH_MITRE, "MITRE ATT&CK Heuristic Tagging", "ENRICHMENT", "true", "Tag events with MITRE ATT&CK techniques based on signatures", true);
        seedDefaultRule(KEY_DLQ_MAX_RETRIES, "DLQ Max Retries", "DLQ_POLICY", "3", "Maximum automated/manual retry attempts for failed events", true);
        seedDefaultRule(KEY_REQUIRE_APPROVAL, "Operator Approval Gate Required", "APPROVAL_POLICY", "true", "Mandate human operator approval before new parsers go live", true);

        refreshCache();
    }

    private void seedDefaultRule(String key, String name, String category, String defaultValue, String desc, boolean enabled) {
        if (ruleRepository.findByRuleKey(key).isEmpty()) {
            Rule r = Rule.builder()
                    .ruleKey(key)
                    .ruleName(name)
                    .ruleCategory(category)
                    .ruleValue(defaultValue)
                    .description(desc)
                    .enabled(enabled)
                    .updatedAt(Instant.now())
                    .updatedBy("SYSTEM")
                    .build();
            ruleRepository.save(r);
        }
    }

    public void refreshCache() {
        List<Rule> rules = ruleRepository.findAll();
        for (Rule r : rules) {
            if (r.isEnabled()) {
                runtimeRuleCache.put(r.getRuleKey(), r.getRuleValue());
            } else {
                runtimeRuleCache.remove(r.getRuleKey());
            }
        }
        log.info("Refreshed {} active operator rules in memory cache", runtimeRuleCache.size());
    }

    public double getDoubleRule(String key, double defaultValue) {
        String val = runtimeRuleCache.get(key);
        if (val != null) {
            try {
                return Double.parseDouble(val);
            } catch (NumberFormatException ignored) {}
        }
        return defaultValue;
    }

    public boolean getBooleanRule(String key, boolean defaultValue) {
        String val = runtimeRuleCache.get(key);
        if (val != null) {
            return Boolean.parseBoolean(val);
        }
        return defaultValue;
    }

    public int getIntRule(String key, int defaultValue) {
        String val = runtimeRuleCache.get(key);
        if (val != null) {
            try {
                return Integer.parseInt(val);
            } catch (NumberFormatException ignored) {}
        }
        return defaultValue;
    }

    public String getStringRule(String key, String defaultValue) {
        return runtimeRuleCache.getOrDefault(key, defaultValue);
    }

    @Transactional
    public Rule updateRule(String ruleKey, String newValue, Boolean enabled, String updatedBy) {
        Rule rule = ruleRepository.findByRuleKey(ruleKey)
                .orElseThrow(() -> new IllegalArgumentException("Rule not found: " + ruleKey));

        if (newValue != null) {
            rule.setRuleValue(newValue);
        }
        if (enabled != null) {
            rule.setEnabled(enabled);
        }
        rule.setUpdatedAt(Instant.now());
        rule.setUpdatedBy(updatedBy != null ? updatedBy : "OPERATOR");

        Rule saved = ruleRepository.save(rule);
        if (saved.isEnabled()) {
            runtimeRuleCache.put(saved.getRuleKey(), saved.getRuleValue());
        } else {
            runtimeRuleCache.remove(saved.getRuleKey());
        }
        log.info("Live updated rule {}: value={}, enabled={}", ruleKey, rule.getRuleValue(), rule.isEnabled());
        return saved;
    }

    public List<Rule> getAllRules() {
        return ruleRepository.findAll();
    }
}
