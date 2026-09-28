package com.ulpf.api;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ulpf.correlation.CorrelationEngine;
import com.ulpf.domain.CorrelatedIncident;
import com.ulpf.domain.NormalizedEvent;
import com.ulpf.domain.SigmaMatch;
import com.ulpf.repository.CorrelatedIncidentRepository;
import com.ulpf.repository.NormalizedEventRepository;
import com.ulpf.repository.SigmaMatchRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.*;

@RestController
@RequestMapping("/api/v1/incidents")
@RequiredArgsConstructor
@Slf4j
public class IncidentApiController {

    private final CorrelatedIncidentRepository incidentRepository;
    private final CorrelationEngine correlationEngine;
    private final NormalizedEventRepository normalizedEventRepository;
    private final SigmaMatchRepository sigmaMatchRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @GetMapping
    @PreAuthorize("hasAnyRole('ANALYST', 'ADMIN')")
    public ResponseEntity<List<CorrelatedIncident>> listIncidents(
            @RequestParam(value = "status", required = false) String status) {
        List<CorrelatedIncident> list;
        if (status != null && !status.isBlank() && !status.equalsIgnoreCase("ALL")) {
            list = incidentRepository.findByStatusOrderByLastSeenAtDesc(status.toUpperCase());
        } else {
            list = incidentRepository.findAllByOrderByLastSeenAtDesc();
        }
        return ResponseEntity.ok(list);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ANALYST', 'ADMIN')")
    public ResponseEntity<?> getIncident(@PathVariable Long id) {
        Optional<CorrelatedIncident> opt = incidentRepository.findById(id);
        if (opt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        CorrelatedIncident incident = opt.get();
        Map<String, Object> response = new HashMap<>();
        response.put("incident", incident);

        // Fetch detailed breakdown of member events
        List<String> eventIds = new ArrayList<>();
        try {
            if (incident.getMemberEventIds() != null) {
                eventIds = objectMapper.readValue(incident.getMemberEventIds(), new TypeReference<List<String>>() {});
            }
        } catch (Exception ignored) {}

        List<Map<String, Object>> memberDetails = new ArrayList<>();
        for (String eventId : eventIds) {
            Map<String, Object> detail = new HashMap<>();
            detail.put("eventId", eventId);
            Optional<NormalizedEvent> normOpt = normalizedEventRepository.findByEventId(eventId);
            if (normOpt.isPresent()) {
                NormalizedEvent ne = normOpt.get();
                detail.put("timestamp", ne.getTimestampUtc());
                detail.put("format", ne.getFormat());
                detail.put("sourceIp", ne.getSourceIp());
                detail.put("destinationIp", ne.getDestinationIp());
                detail.put("destinationPort", ne.getDestinationPort());
                detail.put("action", ne.getAction());
                detail.put("severity", ne.getSeverity());
            }

            List<SigmaMatch> matches = sigmaMatchRepository.findByEventId(eventId);
            if (!matches.isEmpty()) {
                detail.put("matchedRules", matches.stream().map(SigmaMatch::getRuleTitle).toList());
                detail.put("techniqueId", matches.get(0).getTechniqueId());
                detail.put("tactic", matches.get(0).getTactic());
            }
            memberDetails.add(detail);
        }
        response.put("memberEvents", memberDetails);

        return ResponseEntity.ok(response);
    }

    @PatchMapping("/{id}/status")
    @PreAuthorize("hasAnyRole('ANALYST', 'ADMIN')")
    public ResponseEntity<?> updateIncidentStatus(
            @PathVariable Long id,
            @RequestBody Map<String, String> payload) {
        String newStatus = payload.get("status");
        if (newStatus == null || newStatus.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Status field is required"));
        }

        Optional<CorrelatedIncident> opt = incidentRepository.findById(id);
        if (opt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        CorrelatedIncident incident = opt.get();
        incident.setStatus(newStatus.toUpperCase());
        incident.setUpdatedAt(Instant.now());
        CorrelatedIncident saved = incidentRepository.save(incident);

        return ResponseEntity.ok(saved);
    }

    @PostMapping("/correlate/trigger")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> triggerCorrelationScan(
            @RequestParam(value = "windowMinutes", defaultValue = "30") int windowMinutes) {
        List<CorrelatedIncident> results = correlationEngine.correlateWindow(windowMinutes);
        return ResponseEntity.ok(Map.of(
                "status", "COMPLETED",
                "incidentsCreatedOrUpdated", results.size(),
                "incidents", results
        ));
    }
}
