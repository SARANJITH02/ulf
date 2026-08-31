package com.ulpf.ingestion;

import com.ulpf.normalization.NormalizationEngine;
import com.ulpf.normalization.ProcessedLogOutput;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class IngestionService {

    private final NormalizationEngine normalizationEngine;

    public ProcessedLogOutput ingestSingleLog(String rawLog, String source) {
        return normalizationEngine.processLog(rawLog, source);
    }

    public List<ProcessedLogOutput> ingestBulkLogs(List<String> rawLogs, String source) {
        List<ProcessedLogOutput> results = new ArrayList<>();
        if (rawLogs == null || rawLogs.isEmpty()) {
            return results;
        }
        for (String logLine : rawLogs) {
            if (logLine != null && !logLine.isBlank()) {
                results.add(normalizationEngine.processLog(logLine, source != null ? source : "REST_BULK"));
            }
        }
        return results;
    }
}
