package com.ulpf.lineage;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * Pure Java binary Merkle tree implementation for cryptographic ledger batching.
 * Supports tree construction, root computation, inclusion proof generation,
 * and sibling path verification.
 */
public class MerkleTree {

    public enum Direction {
        LEFT, RIGHT
    }

    public static class ProofNode {
        private final String hash;
        private final Direction direction; // position of the sibling relative to current node

        public ProofNode(String hash, Direction direction) {
            this.hash = hash;
            this.direction = direction;
        }

        public String getHash() {
            return hash;
        }

        public Direction getDirection() {
            return direction;
        }

        @Override
        public String toString() {
            return direction + ":" + hash;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            ProofNode proofNode = (ProofNode) o;
            return Objects.equals(hash, proofNode.hash) && direction == proofNode.direction;
        }

        @Override
        public int hashCode() {
            return Objects.hash(hash, direction);
        }
    }

    private final List<String> leaves;
    private final List<List<String>> levels;
    private final String root;

    public MerkleTree(List<String> leafHashes) {
        if (leafHashes == null || leafHashes.isEmpty()) {
            this.leaves = Collections.emptyList();
            this.levels = Collections.emptyList();
            this.root = sha256("");
            return;
        }

        this.leaves = new ArrayList<>(leafHashes);
        this.levels = new ArrayList<>();
        this.root = buildTree();
    }

    private String buildTree() {
        List<String> currentLevel = new ArrayList<>(leaves);
        levels.add(new ArrayList<>(currentLevel));

        while (currentLevel.size() > 1) {
            List<String> nextLevel = new ArrayList<>();
            for (int i = 0; i < currentLevel.size(); i += 2) {
                String left = currentLevel.get(i);
                String right = (i + 1 < currentLevel.size()) ? currentLevel.get(i + 1) : left; // duplicate odd leaf
                nextLevel.add(hashPair(left, right));
            }
            levels.add(new ArrayList<>(nextLevel));
            currentLevel = nextLevel;
        }

        return currentLevel.get(0);
    }

    public String getRoot() {
        return root;
    }

    public List<String> getLeaves() {
        return Collections.unmodifiableList(leaves);
    }

    public int getLeafCount() {
        return leaves.size();
    }

    /**
     * Generate an inclusion proof for the leaf at a given index.
     */
    public List<ProofNode> generateProof(int leafIndex) {
        if (leafIndex < 0 || leafIndex >= leaves.size() || levels.isEmpty()) {
            return Collections.emptyList();
        }

        List<ProofNode> proof = new ArrayList<>();
        int currentIndex = leafIndex;

        for (int levelIdx = 0; levelIdx < levels.size() - 1; levelIdx++) {
            List<String> level = levels.get(levelIdx);
            boolean isRightNode = (currentIndex % 2 == 1);
            int siblingIndex = isRightNode ? currentIndex - 1 : currentIndex + 1;

            if (siblingIndex < level.size()) {
                String siblingHash = level.get(siblingIndex);
                proof.add(new ProofNode(siblingHash, isRightNode ? Direction.LEFT : Direction.RIGHT));
            } else {
                // If odd and node was duplicated with itself
                String siblingHash = level.get(currentIndex);
                proof.add(new ProofNode(siblingHash, Direction.RIGHT));
            }

            currentIndex = currentIndex / 2;
        }

        return proof;
    }

    /**
     * Generate an inclusion proof for the specified leaf hash.
     */
    public List<ProofNode> generateProof(String leafHash) {
        if (leafHash == null) return Collections.emptyList();
        for (int i = 0; i < leaves.size(); i++) {
            if (leafHash.equalsIgnoreCase(leaves.get(i))) {
                return generateProof(i);
            }
        }
        return Collections.emptyList();
    }

    /**
     * Verify an inclusion proof against an expected Merkle root.
     */
    public static boolean verifyProof(String leafHash, List<ProofNode> proof, String expectedRoot) {
        if (leafHash == null || proof == null || expectedRoot == null) {
            return false;
        }

        String currentHash = leafHash.toLowerCase();
        for (ProofNode node : proof) {
            if (node.getDirection() == Direction.LEFT) {
                // Sibling is on the left
                currentHash = hashPair(node.getHash().toLowerCase(), currentHash);
            } else {
                // Sibling is on the right
                currentHash = hashPair(currentHash, node.getHash().toLowerCase());
            }
        }

        return currentHash.equalsIgnoreCase(expectedRoot);
    }

    private static String hashPair(String left, String right) {
        return sha256(left + right);
    }

    public static String sha256(String input) {
        if (input == null) input = "";
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
