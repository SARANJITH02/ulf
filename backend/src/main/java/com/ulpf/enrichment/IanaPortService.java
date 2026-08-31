package com.ulpf.enrichment;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

@Service
@Slf4j
public class IanaPortService {

    private final Map<Integer, String> portServiceMap = new HashMap<>();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @PostConstruct
    public void init() {
        try {
            ClassPathResource resource = new ClassPathResource("iana_ports.json");
            if (resource.exists()) {
                try (InputStream is = resource.getInputStream()) {
                    Map<String, String> rawMap = objectMapper.readValue(is, new TypeReference<Map<String, String>>() {});
                    for (Map.Entry<String, String> entry : rawMap.entrySet()) {
                        try {
                            portServiceMap.put(Integer.parseInt(entry.getKey()), entry.getValue());
                        } catch (NumberFormatException ignored) {}
                    }
                    log.info("Loaded {} IANA port service mappings for offline enrichment", portServiceMap.size());
                }
            }
        } catch (Exception e) {
            log.warn("Failed loading iana_ports.json: {}", e.getMessage());
            // Fallback essential ports
            portServiceMap.put(22, "SSH");
            portServiceMap.put(53, "DNS");
            portServiceMap.put(80, "HTTP");
            portServiceMap.put(443, "HTTPS");
            portServiceMap.put(3389, "RDP");
        }
    }

    public String resolveService(Integer port) {
        if (port == null) return null;
        return portServiceMap.get(port);
    }
}
