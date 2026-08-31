package com.ulpf.repository;

import com.ulpf.domain.Rule;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RuleRepository extends JpaRepository<Rule, Long> {
    Optional<Rule> findByRuleKey(String ruleKey);
    List<Rule> findByEnabledTrue();
    List<Rule> findByRuleCategory(String ruleCategory);
}
