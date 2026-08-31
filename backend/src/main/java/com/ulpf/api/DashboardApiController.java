package com.ulpf.api;

import com.ulpf.metrics.LivePipelineMetrics;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/dashboard")
@RequiredArgsConstructor
public class DashboardApiController {

    private final LivePipelineMetrics liveMetrics;

    @GetMapping("/metrics")
    public ResponseEntity<LivePipelineMetrics.MetricsSnapshot> getMetricsSnapshot() {
        return ResponseEntity.ok(liveMetrics.getSnapshot());
    }
}
