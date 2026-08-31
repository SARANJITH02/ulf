package com.ulpf;

import com.ulpf.detection.FormatClassificationResult;
import com.ulpf.detection.FormatClassifier;
import com.ulpf.detection.LogFormat;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class FormatClassifierTest {

    private FormatClassifier classifier;

    @BeforeEach
    void setUp() {
        classifier = new FormatClassifier();
    }

    @Test
    void testClassify_CiscoSyslog() {
        String log = "<134>Aug 30 10:32:21 cisco-asa %ASA-4-106023: Deny tcp src inside:192.168.1.5/52100 dst outside:10.10.10.20/443";
        FormatClassificationResult res = classifier.classify(log);
        assertThat(res.getFormat()).isEqualTo(LogFormat.SYSLOG_RFC3164);
        assertThat(res.getConfidence()).isGreaterThanOrEqualTo(0.90);
    }

    @Test
    void testClassify_Rfc5424Syslog() {
        String log = "<34>1 2026-08-30T10:32:21.000Z firewall.corp.local myfirewall 1234 ID47 [exampleSDID@32473] Connection blocked";
        FormatClassificationResult res = classifier.classify(log);
        assertThat(res.getFormat()).isEqualTo(LogFormat.SYSLOG_RFC5424);
        assertThat(res.getConfidence()).isGreaterThanOrEqualTo(0.95);
    }

    @Test
    void testClassify_Cef() {
        String log = "CEF:0|Suricata|Network-IDS|6.0.4|2001219|ET SCAN Potential SSH Scan|3|src=192.168.1.150 dst=10.10.10.20 spt=49152 dpt=22 proto=TCP";
        FormatClassificationResult res = classifier.classify(log);
        assertThat(res.getFormat()).isEqualTo(LogFormat.CEF);
        assertThat(res.getConfidence()).isGreaterThanOrEqualTo(0.95);
    }

    @Test
    void testClassify_Leef() {
        String log = "LEEF:1.0|Vendor|Product|Version|EventID|src=192.168.1.200\tdst=10.10.10.50\tdstPort=443\tproto=TCP";
        FormatClassificationResult res = classifier.classify(log);
        assertThat(res.getFormat()).isEqualTo(LogFormat.LEEF);
        assertThat(res.getConfidence()).isGreaterThanOrEqualTo(0.95);
    }

    @Test
    void testClassify_Json() {
        String log = "{\"eventTime\":\"2026-08-30T10:32:21Z\",\"eventSource\":\"signin.amazonaws.com\",\"sourceIPAddress\":\"192.168.1.5\"}";
        FormatClassificationResult res = classifier.classify(log);
        assertThat(res.getFormat()).isEqualTo(LogFormat.JSON);
        assertThat(res.getConfidence()).isGreaterThanOrEqualTo(0.95);
    }

    @Test
    void testClassify_Csv() {
        String log = "1,2026/08/30 10:32:21,001801000001,TRAFFIC,drop,1,2026/08/30 10:32:21,192.168.1.105,10.10.10.35,0.0.0.0,0.0.0.0,rule-block-dmz,jdoe";
        FormatClassificationResult res = classifier.classify(log);
        assertThat(res.getFormat()).isEqualTo(LogFormat.CSV);
        assertThat(res.getConfidence()).isGreaterThanOrEqualTo(0.80);
    }

    @Test
    void testClassify_Unknown() {
        String log = "CUSTOM-ROUTER-HDR [9981] -> session started for token XYZ99";
        FormatClassificationResult res = classifier.classify(log);
        assertThat(res.getFormat()).isEqualTo(LogFormat.UNKNOWN);
    }
}
