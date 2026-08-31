package com.ulpf;

import com.ulpf.normalization.OcsfSchema;
import com.ulpf.parsers.CsvKvParser;
import com.ulpf.parsers.ParsedLogResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CsvKvParserTest {

    private CsvKvParser parser;

    @BeforeEach
    void setUp() {
        parser = new CsvKvParser();
    }

    @Test
    void testParse_PaloAltoCsv() {
        String log = "1,2026/08/30 10:32:21,001801000001,TRAFFIC,drop,1,2026/08/30 10:32:21,192.168.1.105,10.10.10.35,0.0.0.0,0.0.0.0,rule-block-dmz,jdoe,,web-browsing,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/08/30 10:32:21,12345,1,54321,80,0,0,0x0,tcp,deny,1200,600,600,10,2026/08/30 10:32:21,0,any,0,123456789,0x0,192.168.0.0-192.168.255.255,10.0.0.0-10.255.255.255,0,5,5,0,0,,0,0,0,0,";
        ParsedLogResult result = parser.parse(log);

        assertThat(result.isSuccess()).isTrue();
        OcsfSchema ocsf = result.getNormalizedEvent();

        assertThat(ocsf.getSource().getIp()).isEqualTo("192.168.1.105");
        assertThat(ocsf.getDestination().getIp()).isEqualTo("10.10.10.35");
        assertThat(ocsf.getSource().getUser()).isEqualTo("jdoe");
        assertThat(ocsf.getEvent().getAction()).isEqualTo("blocked");
        assertThat(ocsf.getObserver().getVendor()).isEqualTo("Palo Alto Networks");
    }

    @Test
    void testParse_KeyValue() {
        String log = "device=\"FortiGate\" src=192.168.1.75 dst=10.10.10.15 spt=45123 dpt=443 proto=TCP action=deny user=karan";
        ParsedLogResult result = parser.parse(log);

        assertThat(result.isSuccess()).isTrue();
        OcsfSchema ocsf = result.getNormalizedEvent();

        assertThat(ocsf.getSource().getIp()).isEqualTo("192.168.1.75");
        assertThat(ocsf.getDestination().getIp()).isEqualTo("10.10.10.15");
        assertThat(ocsf.getSource().getPort()).isEqualTo(45123);
        assertThat(ocsf.getDestination().getPort()).isEqualTo(443);
        assertThat(ocsf.getEvent().getAction()).isEqualTo("blocked");
        assertThat(ocsf.getSource().getUser()).isEqualTo("karan");
    }
}
