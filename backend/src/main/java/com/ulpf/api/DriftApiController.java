package com.ulpf.api;

import com.ulpf.domain.DriftAlert;
import com.ulpf.parsers.monitoring.ParserDriftMonitorService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/parsers")
@RequiredArgsConstructor
@Slf4j
public class DriftApiController {

    private final ParserDriftMonitorService driftMonitorService;

    @GetMapping("/{name}/drift")
    public ResponseEntity<?> getParserDrift(@PathVariable String name) {
        ParserDriftMonitorService.ParserDriftMetricsDto metrics = driftMonitorService.getParserDriftMetrics(name);
        return ResponseEntity.ok(metrics);
    }

    @GetMapping("/drift-alerts")
    public ResponseEntity<List<DriftAlert>> listDriftAlerts(@RequestParam(required = false) String status) {
        return ResponseEntity.ok(driftMonitorService.listAlerts(status));
    }

    @PatchMapping("/drift-alerts/{id}/acknowledge")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> acknowledgeDriftAlert(@PathVariable Long id, Authentication auth) {
        String username = auth != null ? auth.getName() : "ADMIN";
        Optional<DriftAlert> acked = driftMonitorService.acknowledgeAlert(id, username);
        if (acked.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(acked.get());
    }

    @PostMapping("/drift/check")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> triggerDriftCheck() {
        List<DriftAlert> newAlerts = driftMonitorService.checkDriftNow();
        return ResponseEntity.ok(Map.of(
                "status", "COMPLETED",
                "newAlertsCount", newAlerts.size(),
                "alerts", newAlerts
        ));
    }
}
