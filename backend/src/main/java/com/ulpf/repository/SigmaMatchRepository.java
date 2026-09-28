package com.ulpf.repository;

import com.ulpf.domain.SigmaMatch;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;

@Repository
public interface SigmaMatchRepository extends JpaRepository<SigmaMatch, Long> {

    List<SigmaMatch> findTop50ByOrderByMatchedAtDesc();

    List<SigmaMatch> findByEventId(String eventId);

    @Query("SELECT m FROM SigmaMatch m WHERE " +
           "(:severity IS NULL OR LOWER(m.severity) = LOWER(:severity)) AND " +
           "(:ruleId IS NULL OR m.ruleId = :ruleId) AND " +
           "(:techniqueId IS NULL OR m.techniqueId = :techniqueId) AND " +
           "(:startTime IS NULL OR m.matchedAt >= :startTime) AND " +
           "(:endTime IS NULL OR m.matchedAt <= :endTime) " +
           "ORDER BY m.matchedAt DESC")
    Page<SigmaMatch> searchMatches(
            @Param("severity") String severity,
            @Param("ruleId") String ruleId,
            @Param("techniqueId") String techniqueId,
            @Param("startTime") Instant startTime,
            @Param("endTime") Instant endTime,
            Pageable pageable);

    @Query("SELECT COUNT(m) FROM SigmaMatch m WHERE m.matchedAt >= :since")
    long countMatchesSince(@Param("since") Instant since);

    List<SigmaMatch> findByMatchedAtAfter(Instant since);
}
