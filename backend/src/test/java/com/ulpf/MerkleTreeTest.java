package com.ulpf;

import com.ulpf.lineage.MerkleTree;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class MerkleTreeTest {

    @Test
    @DisplayName("Should build Merkle tree and verify root calculation")
    void testMerkleTreeRootCalculation() {
        List<String> leaves = List.of(
                MerkleTree.sha256("log-event-1"),
                MerkleTree.sha256("log-event-2"),
                MerkleTree.sha256("log-event-3"),
                MerkleTree.sha256("log-event-4")
        );

        MerkleTree tree = new MerkleTree(leaves);
        String root = tree.getRoot();

        assertNotNull(root);
        assertEquals(64, root.length());
        assertEquals(4, tree.getLeafCount());
    }

    @Test
    @DisplayName("Should generate and verify inclusion proof for all leaves")
    void testInclusionProofGenerationAndVerification() {
        List<String> leaves = new ArrayList<>();
        for (int i = 0; i < 7; i++) { // Odd number of leaves to test odd duplication
            leaves.add(MerkleTree.sha256("event-" + i));
        }

        MerkleTree tree = new MerkleTree(leaves);
        String root = tree.getRoot();

        for (int i = 0; i < leaves.size(); i++) {
            String leaf = leaves.get(i);
            List<MerkleTree.ProofNode> proof = tree.generateProof(i);
            assertFalse(proof.isEmpty());

            boolean verified = MerkleTree.verifyProof(leaf, proof, root);
            assertTrue(verified, "Proof failed for leaf index " + i);
        }
    }

    @Test
    @DisplayName("Should detect tampering when leaf hash or sibling is modified")
    void testTamperDetection() {
        List<String> leaves = List.of(
                MerkleTree.sha256("event-alpha"),
                MerkleTree.sha256("event-beta"),
                MerkleTree.sha256("event-gamma")
        );

        MerkleTree tree = new MerkleTree(leaves);
        String root = tree.getRoot();

        List<MerkleTree.ProofNode> proof = tree.generateProof(0);

        // 1. Legitimate proof passes
        assertTrue(MerkleTree.verifyProof(leaves.get(0), proof, root));

        // 2. Tampered leaf hash fails
        String tamperedLeaf = MerkleTree.sha256("event-alpha-tampered");
        assertFalse(MerkleTree.verifyProof(tamperedLeaf, proof, root));

        // 3. Tampered proof node fails
        List<MerkleTree.ProofNode> tamperedProof = new ArrayList<>(proof);
        tamperedProof.set(0, new MerkleTree.ProofNode(MerkleTree.sha256("corrupted-sibling"), MerkleTree.Direction.RIGHT));
        assertFalse(MerkleTree.verifyProof(leaves.get(0), tamperedProof, root));
    }
}
