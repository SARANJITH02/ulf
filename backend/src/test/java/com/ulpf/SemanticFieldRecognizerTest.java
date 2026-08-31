package com.ulpf;

import com.ulpf.inference.SemanticFieldRecognizer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SemanticFieldRecognizerTest {

    private SemanticFieldRecognizer recognizer;

    @BeforeEach
    void setUp() {
        recognizer = new SemanticFieldRecognizer();
    }

    @Test
    void testRecognize_IpAddress() {
        SemanticFieldRecognizer.RecognizedSemanticType res = recognizer.recognize("192.168.1.105", "src", 1);
        assertThat(res.getSemanticType()).isEqualTo("IPV4");
        assertThat(res.getSuggestedOcsfPath()).isEqualTo("source.ip");
        assertThat(res.getConfidence()).isGreaterThanOrEqualTo(0.95);
    }

    @Test
    void testRecognize_IpWithPort() {
        SemanticFieldRecognizer.RecognizedSemanticType res = recognizer.recognize("inside:10.10.10.20:443", "dst", 2);
        assertThat(res.getSemanticType()).isEqualTo("IP_PORT_PAIR");
        assertThat(res.getSuggestedOcsfPath()).isEqualTo("destination.ip");
        assertThat(res.getExtractedValue()).isEqualTo("10.10.10.20");
        assertThat(res.getAuxiliaryValue()).isEqualTo("443");
    }

    @Test
    void testRecognize_ActionKeyword() {
        SemanticFieldRecognizer.RecognizedSemanticType res = recognizer.recognize("DENIED", "", 3);
        assertThat(res.getSemanticType()).isEqualTo("ACTION");
        assertThat(res.getSuggestedOcsfPath()).isEqualTo("event.action");
        assertThat(res.getExtractedValue()).isEqualTo("blocked");
    }

    @Test
    void testRecognize_Protocol() {
        SemanticFieldRecognizer.RecognizedSemanticType res = recognizer.recognize("TCP", "", 4);
        assertThat(res.getSemanticType()).isEqualTo("PROTOCOL");
        assertThat(res.getSuggestedOcsfPath()).isEqualTo("network.protocol");
    }
}
