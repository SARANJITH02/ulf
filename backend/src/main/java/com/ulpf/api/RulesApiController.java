package com.ulpf.api;

import com.ulpf.domain.Rule;
import com.ulpf.rules.RuleEngine;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/rules")
@RequiredArgsConstructor
public class RulesApiController {

    private final RuleEngine ruleEngine;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UpdateRuleRequest {
        private String value;
        private Boolean enabled;
    }

    @GetMapping
    public ResponseEntity<List<Rule>> getRules() {
        return ResponseEntity.ok(ruleEngine.getAllRules());
    }

    @PutMapping("/{ruleKey}")
    public ResponseEntity<?> updateRule(@PathVariable String ruleKey,
                                        @RequestBody UpdateRuleRequest request,
                                        Authentication authentication) {
        String updatedBy = authentication != null ? authentication.getName() : "OPERATOR";
        try {
            Rule updated = ruleEngine.updateRule(ruleKey, request.getValue(), request.getEnabled(), updatedBy);
            return ResponseEntity.ok(updated);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.notFound().build();
        }
    }
}
