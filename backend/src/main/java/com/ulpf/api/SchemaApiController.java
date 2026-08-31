package com.ulpf.api;

import com.ulpf.normalization.EcsAliasMap;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/schema")
@RequiredArgsConstructor
public class SchemaApiController {

    private final EcsAliasMap ecsAliasMap;

    @GetMapping
    public ResponseEntity<?> getSchemaTaxonomy() {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("schemaVersion", "1.1.0-ocsf");
        schema.put("canonicalStandard", "OCSF (Open Cybersecurity Schema Framework)");
        schema.put("supportedCategories", List.of("network_traffic", "authentication", "system_activity", "security_finding"));

        Map<String, String> fieldTypes = new LinkedHashMap<>();
        fieldTypes.put("eventId", "String (UUID)");
        fieldTypes.put("rawEventId", "String (RAW-HashPrefix)");
        fieldTypes.put("rawHashSha256", "String (SHA-256 Digest Hex)");
        fieldTypes.put("timestampUtc", "String (ISO-8601 UTC)");
        fieldTypes.put("event.category", "String (Taxonomy Category)");
        fieldTypes.put("event.type", "String (Device Subtype)");
        fieldTypes.put("event.action", "String (allowed | blocked | denied | dropped | success | failed)");
        fieldTypes.put("event.severity", "String (critical | high | medium | low | informational)");
        fieldTypes.put("source.ip", "String (IPv4 / IPv6)");
        fieldTypes.put("source.port", "Integer (1-65535)");
        fieldTypes.put("source.isInternal", "Boolean (RFC1918 classification)");
        fieldTypes.put("destination.ip", "String (IPv4 / IPv6)");
        fieldTypes.put("destination.port", "Integer (1-65535)");
        fieldTypes.put("destination.isInternal", "Boolean (RFC1918 classification)");
        fieldTypes.put("network.protocol", "String (TCP | UDP | ICMP | GRE | ESP | HTTP | DNS)");
        fieldTypes.put("network.direction", "String (ingress | egress | internal)");
        fieldTypes.put("observer.vendor", "String (Observer Device Vendor)");
        fieldTypes.put("observer.product", "String (Observer Device Product)");
        fieldTypes.put("threat.mitreTechniqueId", "String (e.g. T1110, T1046)");
        fieldTypes.put("threat.mitreTactic", "String (e.g. Discovery, Credential Access)");
        fieldTypes.put("threat.riskScore", "Integer (0-100)");
        fieldTypes.put("extensions", "Map<String, Object> (Lossless unmapped fields)");

        schema.put("fields", fieldTypes);
        schema.put("ecsAliases", ecsAliasMap.getAliases());

        return ResponseEntity.ok(schema);
    }
}
