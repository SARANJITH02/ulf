package com.ulpf;

import com.ulpf.enrichment.IanaPortService;
import com.ulpf.enrichment.MitreMapper;
import com.ulpf.enrichment.OfflineIpClassifier;
import com.ulpf.normalization.OcsfSchema;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OfflineEnrichmentTest {

    private OfflineIpClassifier ipClassifier;
    private IanaPortService portService;
    private MitreMapper mitreMapper;

    @BeforeEach
    void setUp() {
        ipClassifier = new OfflineIpClassifier();
        portService = new IanaPortService();
        portService.init();
        mitreMapper = new MitreMapper();
        mitreMapper.init();
    }

    @Test
    void testIpClassification_Rfc1918() {
        assertThat(ipClassifier.isInternal("192.168.1.1")).isTrue();
        assertThat(ipClassifier.isInternal("10.0.0.50")).isTrue();
        assertThat(ipClassifier.isInternal("172.16.5.10")).isTrue();
        assertThat(ipClassifier.isInternal("8.8.8.8")).isFalse();
        assertThat(ipClassifier.isInternal("1.1.1.1")).isFalse();
    }

    @Test
    void testIanaPortService_WellKnownLookup() {
        assertThat(portService.resolveService(22)).isEqualTo("SSH");
        assertThat(portService.resolveService(443)).isEqualTo("HTTPS");
        assertThat(portService.resolveService(53)).isEqualTo("DNS");
        assertThat(portService.resolveService(3389)).isEqualTo("RDP");
    }

    @Test
    void testMitreMapper_BruteForceHeuristic() {
        OcsfSchema event = OcsfSchema.builder()
                .destination(OcsfSchema.Endpoint.builder().port(22).build())
                .event(OcsfSchema.EventDetail.builder().action("blocked").build())
                .raw(OcsfSchema.RawDetail.builder().message("SSH login failed").build())
                .build();

        OcsfSchema.ThreatDetail threat = mitreMapper.evaluateThreat(event);
        assertThat(threat).isNotNull();
        assertThat(threat.getMitreTechniqueId()).isEqualTo("T1110");
        assertThat(threat.getMitreTechniqueName()).isEqualTo("Brute Force");
    }
}
