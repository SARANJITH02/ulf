package com.ulpf;

import com.ulpf.normalization.OcsfSchema;
import com.ulpf.parsers.CefLeefParser;
import com.ulpf.parsers.ParsedLogResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CefLeefParserTest {

    private CefLeefParser parser;

    @BeforeEach
    void setUp() {
        parser = new CefLeefParser();
    }

    @Test
    void testParse_SuricataCef() {
        String log = "CEF:0|Suricata|Network-IDS|6.0.4|2001219|ET SCAN Potential SSH Scan|3|src=192.168.1.150 dst=10.10.10.20 spt=49152 dpt=22 proto=TCP act=blocked msg=ET SCAN";
        ParsedLogResult result = parser.parse(log);

        assertThat(result.isSuccess()).isTrue();
        OcsfSchema ocsf = result.getNormalizedEvent();
        assertThat(ocsf).isNotNull();

        assertThat(ocsf.getSource().getIp()).isEqualTo("192.168.1.150");
        assertThat(ocsf.getSource().getPort()).isEqualTo(49152);
        assertThat(ocsf.getDestination().getIp()).isEqualTo("10.10.10.20");
        assertThat(ocsf.getDestination().getPort()).isEqualTo(22);
        assertThat(ocsf.getNetwork().getProtocol()).isEqualTo("TCP");
        assertThat(ocsf.getEvent().getAction()).isEqualTo("blocked");
        assertThat(ocsf.getObserver().getVendor()).isEqualTo("Suricata");
        assertThat(ocsf.getObserver().getProduct()).isEqualTo("Network-IDS");
    }

    @Test
    void testParse_QRadarLeef() {
        String log = "LEEF:1.0|IBM|QRadar|7.4|LoginFailure|src=192.168.1.200\tdst=10.10.10.50\tsrcPort=52100\tdstPort=443\tproto=TCP\tusrName=admin";
        ParsedLogResult result = parser.parse(log);

        assertThat(result.isSuccess()).isTrue();
        OcsfSchema ocsf = result.getNormalizedEvent();
        assertThat(ocsf).isNotNull();

        assertThat(ocsf.getSource().getIp()).isEqualTo("192.168.1.200");
        assertThat(ocsf.getDestination().getIp()).isEqualTo("10.10.10.50");
        assertThat(ocsf.getDestination().getPort()).isEqualTo(443);
        assertThat(ocsf.getSource().getUser()).isEqualTo("admin");
    }
}
