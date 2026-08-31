package com.ulpf.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ulpf.domain.NormalizedEvent;
import com.ulpf.domain.RawEvent;
import com.ulpf.lineage.CryptographicLineageService;
import com.ulpf.lineage.IntegrityVerificationResult;
import com.ulpf.normalization.OcsfSchema;
import com.ulpf.repository.NormalizedEventRepository;
import com.ulpf.repository.RawEventRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/events")
@RequiredArgsConstructor
public class EventApiController {

    private final NormalizedEventRepository normalizedEventRepository;
    private final RawEventRepository rawEventRepository;
    private final CryptographicLineageService lineageService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @GetMapping
    public ResponseEntity<?> searchEvents(
            @RequestParam(required = false) String sourceIp,
            @RequestParam(required = false) String destinationIp,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String format,
            @RequestParam(required = false) String parserName,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant startTime,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant endTime,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size) {

        PageRequest pageRequest = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "timestampUtc"));
        Page<NormalizedEvent> events = normalizedEventRepository.searchEvents(
                sourceIp, destinationIp, action, severity, format, parserName, startTime, endTime, pageRequest
        );

        return ResponseEntity.ok(events);
    }

    @GetMapping("/recent")
    public ResponseEntity<List<NormalizedEvent>> getRecentEvents() {
        return ResponseEntity.ok(normalizedEventRepository.findTop50ByOrderByProcessedAtDesc());
    }

    @GetMapping("/{eventId}")
    public ResponseEntity<?> getEventById(@PathVariable String eventId) {
        return normalizedEventRepository.findByEventId(eventId)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/{eventId}/raw")
    public ResponseEntity<?> getRawEventByEventId(@PathVariable String eventId) {
        return normalizedEventRepository.findByEventId(eventId)
                .flatMap(norm -> rawEventRepository.findByRawEventId(norm.getRawEventId()))
                .map(raw -> (ResponseEntity<?>) ResponseEntity.ok(raw))
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/{eventId}/verify")
    public ResponseEntity<IntegrityVerificationResult> verifyEventIntegrity(@PathVariable String eventId) {
        IntegrityVerificationResult result = lineageService.verifyIntegrity(eventId);
        return ResponseEntity.ok(result);
    }
}
