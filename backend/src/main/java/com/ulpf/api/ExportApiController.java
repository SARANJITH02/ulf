package com.ulpf.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ulpf.domain.NormalizedEvent;
import com.ulpf.normalization.OcsfSchema;
import com.ulpf.normalization.ReverseExporter;
import com.ulpf.repository.NormalizedEventRepository;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/export")
@RequiredArgsConstructor
public class ExportApiController {

    private final ReverseExporter reverseExporter;
    private final NormalizedEventRepository normalizedEventRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ExportRequest {
        private String eventId;
        private OcsfSchema event;
        private List<String> eventIds;
        private String targetFormat; // CEF, LEEF, ECS_JSON
    }

    @PostMapping("/cef")
    public ResponseEntity<?> exportToCef(@RequestBody ExportRequest request) {
        OcsfSchema ocsf = resolveOcsf(request);
        if (ocsf == null) {
            return ResponseEntity.badRequest().body("No valid event provided for CEF export");
        }
        String cefWire = reverseExporter.toCefWire(ocsf);
        return ResponseEntity.ok(Map.of("format", "CEF", "wireFormat", cefWire));
    }

    @PostMapping("/leef")
    public ResponseEntity<?> exportToLeef(@RequestBody ExportRequest request) {
        OcsfSchema ocsf = resolveOcsf(request);
        if (ocsf == null) {
            return ResponseEntity.badRequest().body("No valid event provided for LEEF export");
        }
        String leefWire = reverseExporter.toLeefWire(ocsf);
        return ResponseEntity.ok(Map.of("format", "LEEF", "wireFormat", leefWire));
    }

    @PostMapping("/ecs")
    public ResponseEntity<?> exportToEcs(@RequestBody ExportRequest request) {
        OcsfSchema ocsf = resolveOcsf(request);
        if (ocsf == null) {
            return ResponseEntity.badRequest().body("No valid event provided for ECS export");
        }
        return ResponseEntity.ok(reverseExporter.toEcsJson(ocsf));
    }

    @PostMapping("/batch")
    public ResponseEntity<?> exportBatch(@RequestBody ExportRequest request) {
        List<String> ids = request.getEventIds() != null ? request.getEventIds() :
                (request.getEventId() != null ? List.of(request.getEventId()) : Collections.emptyList());

        String format = request.getTargetFormat() != null ? request.getTargetFormat().toUpperCase() : "CEF";
        List<Object> results = new ArrayList<>();

        for (String id : ids) {
            normalizedEventRepository.findByEventId(id).ifPresent(norm -> {
                try {
                    OcsfSchema ocsf = objectMapper.readValue(norm.getOcsfJson(), OcsfSchema.class);
                    if ("CEF".equals(format)) {
                        results.add(reverseExporter.toCefWire(ocsf));
                    } else if ("LEEF".equals(format)) {
                        results.add(reverseExporter.toLeefWire(ocsf));
                    } else {
                        results.add(reverseExporter.toEcsJson(ocsf));
                    }
                } catch (Exception ignored) {}
            });
        }

        return ResponseEntity.ok(Map.of(
                "targetFormat", format,
                "count", results.size(),
                "exportedData", results
        ));
    }

    private OcsfSchema resolveOcsf(ExportRequest request) {
        if (request.getEvent() != null) return request.getEvent();
        if (request.getEventId() != null) {
            return normalizedEventRepository.findByEventId(request.getEventId())
                    .map(norm -> {
                        try {
                            return objectMapper.readValue(norm.getOcsfJson(), OcsfSchema.class);
                        } catch (Exception e) {
                            return null;
                        }
                    }).orElse(null);
        }
        return null;
    }
}
