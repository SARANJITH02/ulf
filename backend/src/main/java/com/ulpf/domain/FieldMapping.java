package com.ulpf.domain;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FieldMapping {
    private String slotName;           // e.g. "token_3" or "field_ip"
    private String canonicalPath;      // e.g. "source.ip", "event.action", "destination.port"
    private String inferredType;       // IPV4, PORT, TIMESTAMP, PROTOCOL, ACTION, STRING
    private Double confidence;         // 0.00 to 1.00
    private String sampleValue;        // "192.168.1.5"
    private boolean userOverridden;    // true if operator modified this mapping
}
