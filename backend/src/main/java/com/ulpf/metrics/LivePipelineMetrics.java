package com.ulpf.metrics;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;

@Component
public class LivePipelineMetrics {

    private final AtomicLong totalEventsProcessed = new AtomicLong(0);
    private final AtomicLong totalSuccessfulEvents = new AtomicLong(0);
    private final AtomicLong totalDlqEvents = new AtomicLong(0);

    private final Map<String, AtomicLong> formatDistribution = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> confidenceDistribution = new ConcurrentHashMap<>();

    private final ConcurrentLinkedQueue<Long> eventTimestamps = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<Double> recentLatencies = new ConcurrentLinkedQueue<>();

    private static final int MAX_LATENCY_SAMPLES = 200;
    private static final long EPS_WINDOW_MS = 5000;

    public LivePipelineMetrics() {
        formatDistribution.put("SYSLOG", new AtomicLong(0));
        formatDistribution.put("CEF", new AtomicLong(0));
        formatDistribution.put("LEEF", new AtomicLong(0));
        formatDistribution.put("JSON", new AtomicLong(0));
        formatDistribution.put("CSV", new AtomicLong(0));
        formatDistribution.put("CUSTOM", new AtomicLong(0));
        formatDistribution.put("UNKNOWN", new AtomicLong(0));

        confidenceDistribution.put("HIGH", new AtomicLong(0));
        confidenceDistribution.put("MEDIUM", new AtomicLong(0));
        confidenceDistribution.put("LOW", new AtomicLong(0));
    }

    public void recordEvent(String format, double confidence, boolean success, double latencyMs) {
        totalEventsProcessed.incrementAndGet();
        if (success) {
            totalSuccessfulEvents.incrementAndGet();
        } else {
            totalDlqEvents.incrementAndGet();
        }

        // Format
        String normFormat = format != null ? format.toUpperCase() : "UNKNOWN";
        formatDistribution.computeIfAbsent(normFormat, k -> new AtomicLong(0)).incrementAndGet();

        // Confidence
        String tier = confidence >= 0.90 ? "HIGH" : (confidence >= 0.70 ? "MEDIUM" : "LOW");
        confidenceDistribution.computeIfAbsent(tier, k -> new AtomicLong(0)).incrementAndGet();

        // Latency
        recentLatencies.add(latencyMs);
        while (recentLatencies.size() > MAX_LATENCY_SAMPLES) {
            recentLatencies.poll();
        }

        // EPS tracking
        long now = System.currentTimeMillis();
        eventTimestamps.add(now);
        cleanOldTimestamps(now);
    }

    private void cleanOldTimestamps(long now) {
        while (!eventTimestamps.isEmpty()) {
            Long head = eventTimestamps.peek();
            if (head != null && (now - head) > EPS_WINDOW_MS) {
                eventTimestamps.poll();
            } else {
                break;
            }
        }
    }

    public double getCurrentEps() {
        long now = System.currentTimeMillis();
        cleanOldTimestamps(now);
        int count = eventTimestamps.size();
        return Math.round((count / (EPS_WINDOW_MS / 1000.0)) * 100.0) / 100.0;
    }

    public MetricsSnapshot getSnapshot() {
        double eps = getCurrentEps();
        long total = totalEventsProcessed.get();
        long succ = totalSuccessfulEvents.get();
        long dlq = totalDlqEvents.get();
        double successRate = total > 0 ? ((double) succ / total) * 100.0 : 100.0;

        List<Double> latencies = new ArrayList<>(recentLatencies);
        Collections.sort(latencies);

        double avgLatency = 0.0;
        double p50 = 0.0;
        double p95 = 0.0;
        double p99 = 0.0;

        if (!latencies.isEmpty()) {
            double sum = 0.0;
            for (Double d : latencies) sum += d;
            avgLatency = Math.round((sum / latencies.size()) * 100.0) / 100.0;
            p50 = Math.round(latencies.get((int) (latencies.size() * 0.50)) * 100.0) / 100.0;
            p95 = Math.round(latencies.get((int) (latencies.size() * 0.95)) * 100.0) / 100.0;
            p99 = Math.round(latencies.get((int) (latencies.size() * 0.99)) * 100.0) / 100.0;
        }

        Map<String, Long> formats = new HashMap<>();
        formatDistribution.forEach((k, v) -> formats.put(k, v.get()));

        Map<String, Long> confidences = new HashMap<>();
        confidenceDistribution.forEach((k, v) -> confidences.put(k, v.get()));

        return MetricsSnapshot.builder()
                .timestamp(Instant.now().toString())
                .eventsPerSecond(eps)
                .totalEvents(total)
                .successfulEvents(succ)
                .dlqEvents(dlq)
                .successRatePercentage(Math.round(successRate * 10.0) / 10.0)
                .avgLatencyMs(avgLatency)
                .p50LatencyMs(p50)
                .p95LatencyMs(p95)
                .p99LatencyMs(p99)
                .formatDistribution(formats)
                .confidenceDistribution(confidences)
                .build();
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class MetricsSnapshot {
        private String timestamp;
        private double eventsPerSecond;
        private long totalEvents;
        private long successfulEvents;
        private long dlqEvents;
        private double successRatePercentage;
        private double avgLatencyMs;
        private double p50LatencyMs;
        private double p95LatencyMs;
        private double p99LatencyMs;
        private Map<String, Long> formatDistribution;
        private Map<String, Long> confidenceDistribution;
    }
}
