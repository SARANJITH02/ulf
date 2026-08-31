package com.ulpf;

import com.ulpf.lineage.CryptographicLineageService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class CryptographicLineageServiceTest {

    @Mock
    private com.ulpf.repository.RawEventRepository rawEventRepository;
    @Mock
    private com.ulpf.repository.NormalizedEventRepository normalizedEventRepository;

    private CryptographicLineageService lineageService;

    @BeforeEach
    void setUp() {
        lineageService = new CryptographicLineageService(rawEventRepository, normalizedEventRepository);
    }

    @Test
    void testComputeSha256_ExactDigest() {
        String logMessage = "<134>Aug 30 10:32:21 cisco-asa %ASA-4-106023: Deny tcp src inside:192.168.1.5/52100 dst outside:10.10.10.20/443";
        String hash1 = lineageService.computeSha256(logMessage);
        String hash2 = lineageService.computeSha256(logMessage);

        assertThat(hash1).isNotNull().hasSize(64);
        assertThat(hash1).isEqualTo(hash2);
    }

    @Test
    void testComputeSha256_TamperSensitivity() {
        String original = "SRC=192.168.1.5 DST=10.0.0.1";
        String tampered = "SRC=192.168.1.6 DST=10.0.0.1";

        String hashOrig = lineageService.computeSha256(original);
        String hashTamp = lineageService.computeSha256(tampered);

        assertThat(hashOrig).isNotEqualTo(hashTamp);
    }

    @Test
    void testGenerateRawEventId() {
        String hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        String rawId = lineageService.generateRawEventId(hash);
        assertThat(rawId).isEqualTo("RAW-e3b0c44298fc1c14");
    }
}
