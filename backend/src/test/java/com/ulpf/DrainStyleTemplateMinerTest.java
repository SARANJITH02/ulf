package com.ulpf;

import com.ulpf.inference.DrainStyleTemplateMiner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DrainStyleTemplateMinerTest {

    private DrainStyleTemplateMiner miner;

    @BeforeEach
    void setUp() {
        miner = new DrainStyleTemplateMiner();
    }

    @Test
    void testMine_StructuralPatternAndDynamicSlots() {
        String log1 = "Aug 30 10:32:21 fw-edge-01 [DROP] proto=TCP src=192.168.1.100:52100 dst=10.10.10.20:443";
        DrainStyleTemplateMiner.TemplateMiningResult result = miner.mine(log1);

        assertThat(result.getTemplate()).contains("proto=<*>");
        assertThat(result.getTemplate()).contains("src=<*>");
        assertThat(result.getTemplate()).contains("dst=<*>");
        assertThat(result.getVariableIndices()).isNotEmpty();
        assertThat(result.getRegexPattern()).contains("token");
    }

    @Test
    void testMine_KeyValuePrePassStructuralTokenPreservation() {
        String rawLog = "SEC-GW-01 2026-08-30T10:32:21Z [BLOCK] proto=TCP src=192.168.10.50:61080 dst=10.10.20.30:40 user=guest";
        DrainStyleTemplateMiner.TemplateMiningResult result = miner.mine(rawLog);

        assertThat(result.getTemplate()).isEqualTo("SEC-GW-01 <*> <*> proto=<*> src=<*> dst=<*> user=<*>");
        assertThat(result.getRegexPattern()).contains("proto=").contains("(?<token3>\\S+)");
        assertThat(result.getRegexPattern()).contains("src=").contains("(?<token4>\\S+)");
        assertThat(result.getRegexPattern()).contains("dst=").contains("(?<token5>\\S+)");
        assertThat(result.getRegexPattern()).contains("user=").contains("(?<token6>\\S+)");
    }
}
