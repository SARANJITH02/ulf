package com.ulpf;

import com.ulpf.normalization.OcsfSchema;
import com.ulpf.parsers.ParsedLogResult;
import com.ulpf.parsers.SyslogRfcParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SyslogRfcParserTest {

    private SyslogRfcParser parser;

    @BeforeEach
    void setUp() {
        parser = new SyslogRfcParser();
    }

    @Test
    void testParse_CiscoAsa_DenyConnection() {
        String log = "<134>Aug 30 10:32:21 cisco-asa %ASA-4-106023: Deny tcp src inside:192.168.1.5/52100 dst outside:10.10.10.20/443 by access-group \"access-group-dmz-01\"";
        ParsedLogResult result = parser.parse(log);

        assertThat(result.isSuccess()).isTrue();
        OcsfSchema ocsf = result.getNormalizedEvent();
        assertThat(ocsf).isNotNull();

        assertThat(ocsf.getSource().getIp()).isEqualTo("192.168.1.5");
        assertThat(ocsf.getSource().getPort()).isEqualTo(52100);
        assertThat(ocsf.getDestination().getIp()).isEqualTo("10.10.10.20");
        assertThat(ocsf.getDestination().getPort()).isEqualTo(443);
        assertThat(ocsf.getNetwork().getProtocol()).isEqualTo("TCP");
        assertThat(ocsf.getEvent().getAction()).isEqualTo("blocked");
        assertThat(ocsf.getObserver().getVendor()).isEqualTo("Cisco");
        assertThat(ocsf.getExtensions().get("ciscoRuleId")).isEqualTo("access-group-dmz-01");
        assertThat(ocsf.getExtensions().get("vendorCode")).isEqualTo("%ASA-4-106023");
    }

    @Test
    void testParse_Iptables_Drop() {
        String log = "<13>Aug 30 10:32:21 fw01 kernel: DROP IN=eth0 OUT=eth1 SRC=192.168.1.50 DST=10.0.0.10 PROTO=TCP SPT=55432 DPT=22";
        ParsedLogResult result = parser.parse(log);

        assertThat(result.isSuccess()).isTrue();
        OcsfSchema ocsf = result.getNormalizedEvent();
        assertThat(ocsf).isNotNull();

        assertThat(ocsf.getSource().getIp()).isEqualTo("192.168.1.50");
        assertThat(ocsf.getSource().getPort()).isEqualTo(55432);
        assertThat(ocsf.getDestination().getIp()).isEqualTo("10.0.0.10");
        assertThat(ocsf.getDestination().getPort()).isEqualTo(22);
        assertThat(ocsf.getNetwork().getProtocol()).isEqualTo("TCP");
        assertThat(ocsf.getEvent().getAction()).isEqualTo("blocked");
    }
}
