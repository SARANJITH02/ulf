package com.ulpf.repository;

import com.ulpf.domain.ParserVersion;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ParserVersionRepository extends JpaRepository<ParserVersion, Long> {
    List<ParserVersion> findByParserIdOrderByCreatedAtDesc(Long parserId);
    Optional<ParserVersion> findByParserIdAndActiveTrue(Long parserId);
}
