package com.ulpf.normalization;

import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class EcsAliasMap {

    private static final Map<String, String> OCSF_TO_ECS_MAP;

    static {
        Map<String, String> map = new LinkedHashMap<>();
        map.put("timestampUtc", "@timestamp");
        map.put("source.ip", "source.ip");
        map.put("source.port", "source.port");
        map.put("source.hostname", "source.domain");
        map.put("source.user", "source.user.name");
        map.put("destination.ip", "destination.ip");
        map.put("destination.port", "destination.port");
        map.put("destination.hostname", "destination.domain");
        map.put("network.protocol", "network.transport");
        map.put("network.direction", "network.direction");
        map.put("network.bytesIn", "source.bytes");
        map.put("network.bytesOut", "destination.bytes");
        map.put("event.action", "event.action");
        map.put("event.category", "event.category");
        map.put("event.type", "event.type");
        map.put("event.severity", "event.severity");
        map.put("observer.vendor", "observer.vendor");
        map.put("observer.product", "observer.product");
        map.put("observer.hostname", "observer.hostname");
        map.put("threat.techniqueId", "threat.technique.id");
        map.put("threat.techniqueName", "threat.technique.name");
        map.put("threat.tactic", "threat.tactic.name");
        map.put("threat.riskScore", "threat.indicator.confidence");
        map.put("raw.message", "event.original");
        map.put("rawHashSha256", "event.hash.sha256");
        OCSF_TO_ECS_MAP = Collections.unmodifiableMap(map);
    }

    public Map<String, String> getAliases() {
        return OCSF_TO_ECS_MAP;
    }

    public String getEcsField(String ocsfField) {
        return OCSF_TO_ECS_MAP.getOrDefault(ocsfField, ocsfField);
    }
}
