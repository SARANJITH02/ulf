package com.ulpf.metrics;

import com.ulpf.normalization.OcsfSchema;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@EnableScheduling
@RequiredArgsConstructor
@Slf4j
public class MetricsBroadcaster {

    private final SimpMessagingTemplate messagingTemplate;
    private final LivePipelineMetrics liveMetrics;

    @Scheduled(fixedRate = 1000)
    public void broadcastMetrics() {
        try {
            LivePipelineMetrics.MetricsSnapshot snapshot = liveMetrics.getSnapshot();
            messagingTemplate.convertAndSend("/topic/metrics", snapshot);
        } catch (Exception e) {
            log.trace("Metric broadcast skipped (no active subscribers): {}", e.getMessage());
        }
    }

    public void broadcastEvent(OcsfSchema event) {
        if (event == null) return;
        try {
            messagingTemplate.convertAndSend("/topic/events", event);
        } catch (Exception e) {
            log.trace("Event broadcast skipped: {}", e.getMessage());
        }
    }

    public void broadcastAlert(Object alert) {
        if (alert == null) return;
        try {
            messagingTemplate.convertAndSend("/topic/alerts", alert);
        } catch (Exception e) {
            log.trace("Alert broadcast skipped: {}", e.getMessage());
        }
    }
}
