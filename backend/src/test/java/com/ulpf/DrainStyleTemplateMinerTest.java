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

        assertThat(result.getTemplate()).contains("<*>");
        assertThat(result.getVariableIndices()).isNotEmpty();
        assertThat(result.getRegexPattern()).contains("token");
    }
}
