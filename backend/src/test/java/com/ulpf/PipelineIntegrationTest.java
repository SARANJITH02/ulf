package com.ulpf;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ulpf.security.AuthController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class PipelineIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String adminToken;

    @BeforeEach
    void setUp() throws Exception {
        // Authenticate admin user
        AuthController.LoginRequest login = new AuthController.LoginRequest("admin", "admin123");
        MvcResult authResult = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(login)))
                .andExpect(status().isOk())
                .andReturn();

        Map<?, ?> map = objectMapper.readValue(authResult.getResponse().getContentAsString(), Map.class);
        adminToken = "Bearer " + map.get("token");
    }

    @Test
    void testEndToEndPipeline_Ingest_Query_Verify() throws Exception {
        // 1. Ingest Cisco Syslog
        String rawLog = "<134>Aug 30 10:32:21 cisco-asa %ASA-4-106023: Deny tcp src inside:192.168.1.5/52100 dst outside:10.10.10.20/443 by access-group \"access-group-dmz-01\"";
        MvcResult ingestResult = mockMvc.perform(post("/api/v1/ingest")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("message", rawLog))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.eventId").isNotEmpty())
                .andExpect(jsonPath("$.rawHashSha256").isNotEmpty())
                .andReturn();

        Map<?, ?> ingestResponse = objectMapper.readValue(ingestResult.getResponse().getContentAsString(), Map.class);
        String eventId = (String) ingestResponse.get("eventId");
        assertThat(eventId).isNotNull();

        // 2. Query Normalized Event
        mockMvc.perform(get("/api/v1/events/" + eventId)
                        .header("Authorization", adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.eventId").value(eventId))
                .andExpect(jsonPath("$.action").value("blocked"));

        // 3. Cryptographic Verification
        mockMvc.perform(get("/api/v1/events/" + eventId + "/verify")
                        .header("Authorization", adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verified").value(true))
                .andExpect(jsonPath("$.storedRawHash").isNotEmpty())
                .andExpect(jsonPath("$.recomputedRawHash").isNotEmpty());

        // 4. Schema endpoint
        mockMvc.perform(get("/api/v1/schema"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.schemaVersion").value("1.1.0-ocsf"));

        // 5. Rules endpoint
        mockMvc.perform(get("/api/v1/rules")
                        .header("Authorization", adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }
}
