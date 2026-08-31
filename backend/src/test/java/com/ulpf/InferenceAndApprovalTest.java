package com.ulpf;

import com.ulpf.detection.LogFormat;
import com.ulpf.inference.DrainInferenceEngine;
import com.ulpf.inference.DrainStyleTemplateMiner;
import com.ulpf.inference.InferenceResult;
import com.ulpf.inference.RegexParserSynthesizer;
import com.ulpf.inference.SemanticFieldRecognizer;
import com.ulpf.normalization.ConfidenceScorer;
import com.ulpf.normalization.OcsfSchema;
import com.ulpf.parsers.DynamicGeneratedParser;
import com.ulpf.parsers.DynamicParserRegistry;
import com.ulpf.parsers.ParsedLogResult;
import com.ulpf.repository.ParserEntityRepository;
import com.ulpf.repository.ParserVersionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class InferenceAndApprovalTest {

    private DrainInferenceEngine inferenceEngine;
    private DynamicParserRegistry parserRegistry;
    private RegexParserSynthesizer synthesizer;

    @Mock
    private ParserEntityRepository parserEntityRepository;
    @Mock
    private ParserVersionRepository parserVersionRepository;

    @BeforeEach
    void setUp() {
        DrainStyleTemplateMiner miner = new DrainStyleTemplateMiner();
        SemanticFieldRecognizer recognizer = new SemanticFieldRecognizer();
        ConfidenceScorer scorer = new ConfidenceScorer();

        inferenceEngine = new DrainInferenceEngine(miner, recognizer, scorer);
        synthesizer = new RegexParserSynthesizer();
        parserRegistry = new DynamicParserRegistry(Collections.emptyList(), parserEntityRepository, parserVersionRepository, synthesizer);
    }

    @Test
    void testEndToEndUnknownLogLabWorkflow() {
        // Step 1: Unknown log arrives in Unknown Log Lab
        String unknownSample1 = "SEC-GW-01 2026-08-30T10:32:21Z [BLOCK] proto=TCP src=192.168.10.50:61000 dst=10.20.30.40:80 user=guest";
        InferenceResult inference = inferenceEngine.infer(unknownSample1);

        assertThat(inference).isNotNull();
        assertThat(inference.getMinedTemplate()).isNotEmpty();
        assertThat(inference.getInferredMappings()).isNotEmpty();
        assertThat(inference.getOverallConfidence()).isGreaterThanOrEqualTo(0.80);

        // Step 2: Operator reviews and explicitly APPROVES the synthesized parser
        DynamicGeneratedParser approvedParser = synthesizer.synthesize(
                "custom_sec_gateway",
                "Custom Security Gateway Parser",
                "1.0",
                "CUSTOM",
                inference.getMinedTemplate(),
                inference.getSynthesizedRegex(),
                inference.getInferredMappings(),
                inference.getOverallConfidence()
        );

        // Step 3: Hot-register approved parser into DynamicParserRegistry (Zero Restart)
        parserRegistry.registerApprovedParser(approvedParser);

        // Step 4: The next event from that source arrives — parses automatically!
        String unknownSample2 = "SEC-GW-01 2026-08-30T10:32:21Z [BLOCK] proto=TCP src=192.168.10.50:61000 dst=10.20.30.40:80 user=guest";
        assertThat(approvedParser.canParse(unknownSample2, LogFormat.UNKNOWN)).isTrue();

        ParsedLogResult parseResult = approvedParser.parse(unknownSample2);
        assertThat(parseResult.isSuccess()).isTrue();

        OcsfSchema ocsf = parseResult.getNormalizedEvent();
        assertThat(ocsf).isNotNull();
        assertThat(ocsf.getSource().getIp()).isEqualTo("192.168.10.50");
        assertThat(ocsf.getDestination().getIp()).isEqualTo("10.20.30.40");
        assertThat(ocsf.getEvent().getAction()).isEqualTo("blocked");
        assertThat(ocsf.getSource().getUser()).isEqualTo("guest");
    }
}
