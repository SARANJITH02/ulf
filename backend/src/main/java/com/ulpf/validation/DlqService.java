package com.ulpf.validation;

import com.ulpf.domain.DlqEntry;
import com.ulpf.repository.DlqEntryRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class DlqService {

    private final DlqEntryRepository dlqEntryRepository;

    @Transactional
    public DlqEntry sendToDlq(String rawEventId, String rawMessage, String failureCode, String failureReason, String detectedFormat) {
        log.warn("Routing event to Dead-Letter Queue (DLQ): rawEventId={}, code={}, reason={}", rawEventId, failureCode, failureReason);

        DlqEntry entry = DlqEntry.builder()
                .rawEventId(rawEventId)
                .rawMessage(rawMessage)
                .failureCode(failureCode)
                .failureReason(failureReason)
                .detectedFormat(detectedFormat != null ? detectedFormat : "UNKNOWN")
                .retryCount(0)
                .status("NEW")
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

        return dlqEntryRepository.save(entry);
    }

    @Transactional(readOnly = true)
    public Page<DlqEntry> listDlq(String status, Pageable pageable) {
        if (status != null && !status.isBlank()) {
            return dlqEntryRepository.findByStatusOrderByCreatedAtDesc(status, pageable);
        }
        return dlqEntryRepository.findAll(pageable);
    }

    @Transactional(readOnly = true)
    public List<DlqEntry> getRecentDlq() {
        return dlqEntryRepository.findTop50ByOrderByCreatedAtDesc();
    }

    @Transactional(readOnly = true)
    public Optional<DlqEntry> getDlqEntry(Long id) {
        return dlqEntryRepository.findById(id);
    }

    @Transactional
    public Optional<DlqEntry> markRetried(Long id) {
        return dlqEntryRepository.findById(id).map(entry -> {
            entry.setRetryCount((entry.getRetryCount() != null ? entry.getRetryCount() : 0) + 1);
            entry.setStatus("RETRIED");
            entry.setUpdatedAt(Instant.now());
            return dlqEntryRepository.save(entry);
        });
    }

    @Transactional
    public Optional<DlqEntry> resolveDlq(Long id, String resolutionStatus) {
        return dlqEntryRepository.findById(id).map(entry -> {
            entry.setStatus(resolutionStatus != null ? resolutionStatus : "RESOLVED");
            entry.setUpdatedAt(Instant.now());
            return dlqEntryRepository.save(entry);
        });
    }

    @Transactional(readOnly = true)
    public long countActiveDlq() {
        return dlqEntryRepository.countByStatus("NEW");
    }
}
