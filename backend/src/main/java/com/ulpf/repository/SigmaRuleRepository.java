package com.ulpf.repository;

import com.ulpf.domain.SigmaRule;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SigmaRuleRepository extends JpaRepository<SigmaRule, String> {

    List<SigmaRule> findAllByOrderByCreatedAtDesc();

    List<SigmaRule> findByEnabledTrue();

    Optional<SigmaRule> findById(String id);
}
