package com.ulpf.api;

import com.ulpf.ingestion.IngestionService;
import com.ulpf.normalization.ProcessedLogOutput;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/ingest")
@RequiredArgsConstructor
public class IngestionApiController {

    private final IngestionService ingestionService;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class IngestSingleRequest {
        private String log;
        private String message;
        private String source;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class IngestBulkRequest {
        private List<String> logs;
        private String source;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class IngestResponse {
        private boolean success;
        private int totalReceived;
        private int totalProcessed;
        private List<ProcessedLogOutput> events;
    }

    @PostMapping
    public ResponseEntity<?> ingestSingleOrBulk(@RequestBody Object payload) {
        if (payload instanceof String str) {
            ProcessedLogOutput out = ingestionService.ingestSingleLog(str, "REST_SINGLE");
            return ResponseEntity.ok(out);
        }

        // Check if string list or single JSON request
        if (payload instanceof List<?> list) {
            List<String> strList = list.stream().map(Object::toString).toList();
            List<ProcessedLogOutput> outs = ingestionService.ingestBulkLogs(strList, "REST_BULK");
            return ResponseEntity.ok(IngestResponse.builder()
                    .success(true)
                    .totalReceived(strList.size())
                    .totalProcessed(outs.size())
                    .events(outs)
                    .build());
        }

        if (payload instanceof java.util.Map<?, ?> map) {
            if (map.containsKey("logs") && map.get("logs") instanceof List<?> list) {
                List<String> strList = list.stream().map(Object::toString).toList();
                String src = map.containsKey("source") ? map.get("source").toString() : "REST_BULK";
                List<ProcessedLogOutput> outs = ingestionService.ingestBulkLogs(strList, src);
                return ResponseEntity.ok(IngestResponse.builder()
                        .success(true)
                        .totalReceived(strList.size())
                        .totalProcessed(outs.size())
                        .events(outs)
                        .build());
            }

            String logContent = map.containsKey("log") ? map.get("log").toString() :
                    (map.containsKey("message") ? map.get("message").toString() : map.toString());
            String src = map.containsKey("source") ? map.get("source").toString() : "REST_SINGLE";
            ProcessedLogOutput out = ingestionService.ingestSingleLog(logContent, src);
            return ResponseEntity.ok(out);
        }

        return ResponseEntity.badRequest().body("Unrecognized payload format");
    }
}
