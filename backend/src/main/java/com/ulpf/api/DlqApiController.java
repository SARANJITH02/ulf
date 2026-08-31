package com.ulpf.api;

import com.ulpf.domain.DlqEntry;
import com.ulpf.ingestion.IngestionService;
import com.ulpf.normalization.ProcessedLogOutput;
import com.ulpf.validation.DlqService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/dlq")
@RequiredArgsConstructor
public class DlqApiController {

    private final DlqService dlqService;
    private final IngestionService ingestionService;

    @GetMapping
    public ResponseEntity<Page<DlqEntry>> listDlq(
            @RequestParam(required = false) String status,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size) {
        PageRequest pageRequest = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        return ResponseEntity.ok(dlqService.listDlq(status, pageRequest));
    }

    @GetMapping("/recent")
    public ResponseEntity<List<DlqEntry>> getRecentDlq() {
        return ResponseEntity.ok(dlqService.getRecentDlq());
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getDlqEntry(@PathVariable Long id) {
        return dlqService.getDlqEntry(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/{id}/retry")
    public ResponseEntity<?> retryDlqEntry(@PathVariable Long id) {
        return dlqService.getDlqEntry(id).map(entry -> {
            dlqService.markRetried(id);
            ProcessedLogOutput result = ingestionService.ingestSingleLog(entry.getRawMessage(), "DLQ_RETRY");
            if (result.isSuccess()) {
                dlqService.resolveDlq(id, "RESOLVED_ON_RETRY");
            }
            return ResponseEntity.ok(Map.of(
                    "dlqId", id,
                    "retried", true,
                    "pipelineResult", result
            ));
        }).orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/{id}/resolve")
    public ResponseEntity<?> resolveDlqEntry(@PathVariable Long id, @RequestParam(defaultValue = "RESOLVED") String status) {
        return dlqService.resolveDlq(id, status)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }
}
