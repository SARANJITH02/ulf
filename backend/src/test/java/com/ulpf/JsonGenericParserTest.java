package com.ulpf;

import com.ulpf.normalization.OcsfSchema;
import com.ulpf.parsers.JsonGenericParser;
import com.ulpf.parsers.ParsedLogResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class JsonGenericParserTest {

    private JsonGenericParser parser;

    @BeforeEach
    void setUp() {
        parser = new JsonGenericParser();
    }

    @Test
    void testParse_AwsCloudTrail() {
        String log = """
        {
          "eventVersion": "1.08",
          "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE",
            "userName": "security_admin"
          },
          "eventTime": "2026-08-30T10:32:21Z",
          "eventSource": "iam.amazonaws.com",
          "eventName": "CreateUser",
          "awsRegion": "us-east-1",
          "sourceIPAddress": "192.168.1.100"
        }
        """;

        ParsedLogResult result = parser.parse(log);
        assertThat(result.isSuccess()).isTrue();
        OcsfSchema ocsf = result.getNormalizedEvent();

        assertThat(ocsf.getSource().getIp()).isEqualTo("192.168.1.100");
        assertThat(ocsf.getSource().getUser()).isEqualTo("security_admin");
        assertThat(ocsf.getObserver().getVendor()).isEqualTo("AWS");
        assertThat(ocsf.getObserver().getProduct()).isEqualTo("CloudTrail");
    }

    @Test
    void testParse_SuricataEve() {
        String log = """
        {
          "timestamp": "2026-08-30T10:32:21.000Z",
          "flow_id": 1234567890,
          "event_type": "alert",
          "src_ip": "192.168.1.55",
          "src_port": 54321,
          "dest_ip": "10.10.10.25",
          "dest_port": 80,
          "proto": "TCP",
          "alert": {
            "action": "blocked",
            "signature": "ET MALWARE Suspicious User-Agent",
            "severity": 1
          }
        }
        """;

        ParsedLogResult result = parser.parse(log);
        assertThat(result.isSuccess()).isTrue();
        OcsfSchema ocsf = result.getNormalizedEvent();

        assertThat(ocsf.getSource().getIp()).isEqualTo("192.168.1.55");
        assertThat(ocsf.getSource().getPort()).isEqualTo(54321);
        assertThat(ocsf.getDestination().getIp()).isEqualTo("10.10.10.25");
        assertThat(ocsf.getDestination().getPort()).isEqualTo(80);
        assertThat(ocsf.getNetwork().getProtocol()).isEqualTo("TCP");
        assertThat(ocsf.getEvent().getAction()).isEqualTo("blocked");
        assertThat(ocsf.getObserver().getVendor()).isEqualTo("Suricata");
    }
}
