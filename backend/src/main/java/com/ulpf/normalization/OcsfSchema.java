package com.ulpf.normalization;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashMap;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OcsfSchema {

    private String eventId;
    private String rawEventId;
    private String rawHashSha256;
    private String timestampUtc; // ISO-8601 UTC

    @Builder.Default
    private EventDetail event = new EventDetail();

    @Builder.Default
    private Endpoint source = new Endpoint();

    @Builder.Default
    private Endpoint destination = new Endpoint();

    @Builder.Default
    private NetworkDetail network = new NetworkDetail();

    @Builder.Default
    private ObserverDetail observer = new ObserverDetail();

    @Builder.Default
    private ThreatDetail threat = new ThreatDetail();

    @Builder.Default
    private RawDetail raw = new RawDetail();

    @Builder.Default
    private Map<String, Object> extensions = new HashMap<>();

    @Builder.Default
    private UlpfMetadata ulpf = new UlpfMetadata();

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class EventDetail {
        private String category;    // network_traffic, authentication, system_activity
        private String type;        // firewall, ids, vpn, router, proxy
        private String action;      // allowed, blocked, denied, dropped, failed, success
        private String severity;    // critical, high, medium, low, informational
        private Integer severityId; // 1-5
        private String message;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Endpoint {
        private String ip;
        private Integer port;
        private String hostname;
        private String user;
        private Boolean isInternal;
        private String mac;
        private String zone;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class NetworkDetail {
        private String protocol;      // TCP, UDP, ICMP, etc.
        private String direction;     // ingress, egress, internal
        private Long bytesIn;
        private Long bytesOut;
        private Long packets;
        private String transport;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class ObserverDetail {
        private String vendor;        // Cisco, Palo Alto, Fortinet, Suricata, AWS
        private String product;       // ASA, PAN-OS, FortiGate, EVE, CloudTrail
        private String hostname;
        private String version;
        private String type;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class ThreatDetail {
        private Integer riskScore;
        private String mitreTechniqueId;
        private String mitreTechniqueName;
        private String mitreTactic;
        private String category;
        @Builder.Default
        private java.util.List<SigmaMatchSummary> sigmaMatches = new java.util.ArrayList<>();
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class SigmaMatchSummary {
        private String ruleId;
        private String ruleTitle;
        private String severity;
        private String techniqueId;
        private String tactic;
        private String matchedDetails;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class RawDetail {
        private String message;
        private String format;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class UlpfMetadata {
        @Builder.Default
        private String schemaVersion = "1.1.0-ocsf";
        private String parserName;
        private String parserVersion;
        @Builder.Default
        private Map<String, Double> mappingConfidence = new HashMap<>();
        private Double averageConfidence;
        @Builder.Default
        private String dlqStatus = "NORMAL";
        @Builder.Default
        private Map<String, String> ecsAliases = new HashMap<>();
    }
}
