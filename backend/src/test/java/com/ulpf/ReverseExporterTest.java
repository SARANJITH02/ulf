package com.ulpf;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.ulpf.normalization.EcsAliasMap;
import com.ulpf.normalization.OcsfSchema;
import com.ulpf.normalization.ReverseExporter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ReverseExporterTest {

    private ReverseExporter exporter;

    @BeforeEach
    void setUp() {
        exporter = new ReverseExporter(new EcsAliasMap());
    }

    @Test
    void testToCefWire() {
        OcsfSchema ocsf = OcsfSchema.builder()
                .eventId("ULPF-12345")
                .event(OcsfSchema.EventDetail.builder().action("blocked").severityId(4).type("firewall").message("Traffic Blocked").build())
                .source(OcsfSchema.Endpoint.builder().ip("192.168.1.5").port(52100).build())
                .destination(OcsfSchema.Endpoint.builder().ip("10.10.10.20").port(443).build())
                .network(OcsfSchema.NetworkDetail.builder().protocol("TCP").build())
                .observer(OcsfSchema.ObserverDetail.builder().vendor("Cisco").product("ASA").version("9.1").build())
                .build();

        String cef = exporter.toCefWire(ocsf);
        assertThat(cef).startsWith("CEF:0|Cisco|ASA|9.1|firewall|Traffic Blocked|4|");
        assertThat(cef).contains("src=192.168.1.5");
        assertThat(cef).contains("dst=10.10.10.20");
        assertThat(cef).contains("dpt=443");
    }

    @Test
    void testToLeefWire() {
        OcsfSchema ocsf = OcsfSchema.builder()
                .eventId("ULPF-12345")
                .event(OcsfSchema.EventDetail.builder().action("allowed").type("audit").build())
                .source(OcsfSchema.Endpoint.builder().ip("192.168.1.200").port(52100).user("admin").build())
                .destination(OcsfSchema.Endpoint.builder().ip("10.10.10.50").port(443).build())
                .network(OcsfSchema.NetworkDetail.builder().protocol("TCP").build())
                .observer(OcsfSchema.ObserverDetail.builder().vendor("IBM").product("QRadar").version("7.4").build())
                .build();

        String leef = exporter.toLeefWire(ocsf);
        assertThat(leef).startsWith("LEEF:1.0|IBM|QRadar|7.4|audit|");
        assertThat(leef).contains("src=192.168.1.200");
        assertThat(leef).contains("usrName=admin");
    }

    @Test
    void testToEcsJson() {
        OcsfSchema ocsf = OcsfSchema.builder()
                .timestampUtc("2026-08-30T10:32:21.000Z")
                .eventId("ULPF-12345")
                .event(OcsfSchema.EventDetail.builder().action("blocked").build())
                .source(OcsfSchema.Endpoint.builder().ip("192.168.1.5").build())
                .destination(OcsfSchema.Endpoint.builder().ip("10.10.10.20").build())
                .build();

        ObjectNode ecs = exporter.toEcsJson(ocsf);
        assertThat(ecs.has("@timestamp")).isTrue();
        assertThat(ecs.path("source").path("ip").asText()).isEqualTo("192.168.1.5");
        assertThat(ecs.path("destination").path("ip").asText()).isEqualTo("10.10.10.20");
    }
}
