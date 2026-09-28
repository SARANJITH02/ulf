package com.ulpf.api;

import com.ulpf.domain.SigmaMatch;
import com.ulpf.domain.SigmaRule;
import com.ulpf.repository.SigmaMatchRepository;
import com.ulpf.rules.SigmaRuleService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
@Slf4j
public class SigmaApiController {

    private final SigmaRuleService sigmaRuleService;
    private final SigmaMatchRepository sigmaMatchRepository;

    @GetMapping("/rules/sigma")
    public ResponseEntity<List<SigmaRule>> listSigmaRules() {
        return ResponseEntity.ok(sigmaRuleService.listAllRules());
    }

    @GetMapping("/rules/sigma/{id}")
    public ResponseEntity<?> getSigmaRule(@PathVariable String id) {
        Optional<SigmaRule> ruleOpt = sigmaRuleService.getRuleById(id);
        if (ruleOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(ruleOpt.get());
    }

    @PostMapping("/rules/sigma")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createSigmaRule(@RequestBody Map<String, String> payload, Authentication auth) {
        String yamlText = payload.get("sigmaYaml");
        if (yamlText == null || yamlText.isBlank()) {
            yamlText = payload.get("yaml");
        }
        if (yamlText == null || yamlText.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Field 'sigmaYaml' is required"));
        }

        String username = auth != null ? auth.getName() : "ADMIN";
        try {
            SigmaRule created = sigmaRuleService.createOrUpdateRule(yamlText, username);
            return ResponseEntity.ok(created);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PatchMapping("/rules/sigma/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> updateSigmaRule(@PathVariable String id, @RequestBody Map<String, Object> payload) {
        if (payload.containsKey("enabled")) {
            boolean enabled = Boolean.parseBoolean(payload.get("enabled").toString());
            Optional<SigmaRule> updated = sigmaRuleService.toggleRule(id, enabled);
            if (updated.isEmpty()) {
                return ResponseEntity.notFound().build();
            }
            return ResponseEntity.ok(updated.get());
        }

        if (payload.containsKey("sigmaYaml")) {
            String yaml = payload.get("sigmaYaml").toString();
            try {
                SigmaRule updated = sigmaRuleService.createOrUpdateRule(yaml, "ADMIN");
                return ResponseEntity.ok(updated);
            } catch (Exception e) {
                return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
            }
        }

        return ResponseEntity.badRequest().body(Map.of("error", "Specify 'enabled' or 'sigmaYaml' to update"));
    }

    @DeleteMapping("/rules/sigma/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteSigmaRule(@PathVariable String id) {
        boolean deleted = sigmaRuleService.deleteRule(id);
        if (!deleted) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(Map.of("status", "DELETED", "id", id));
    }

    @GetMapping("/alerts")
    public ResponseEntity<Page<SigmaMatch>> listAlerts(
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String ruleId,
            @RequestParam(required = false) String techniqueId,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant startTime,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant endTime,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size) {

        PageRequest pageRequest = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "matchedAt"));
        Page<SigmaMatch> results = sigmaMatchRepository.searchMatches(severity, ruleId, techniqueId, startTime, endTime, pageRequest);
        return ResponseEntity.ok(results);
    }
}
