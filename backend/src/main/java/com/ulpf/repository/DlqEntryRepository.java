package com.ulpf.repository;

import com.ulpf.domain.DlqEntry;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface DlqEntryRepository extends JpaRepository<DlqEntry, Long> {
    Optional<DlqEntry> findByRawEventId(String rawEventId);
    Page<DlqEntry> findByStatusOrderByCreatedAtDesc(String status, Pageable pageable);
    List<DlqEntry> findTop50ByOrderByCreatedAtDesc();
    long countByStatus(String status);
    long countByDetectedFormat(String detectedFormat);
    long countByDetectedFormatAndCreatedAtAfter(String detectedFormat, java.time.Instant since);
}
