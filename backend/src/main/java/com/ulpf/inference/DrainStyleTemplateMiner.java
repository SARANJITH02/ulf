package com.ulpf.inference;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Pattern;

@Component
public class DrainStyleTemplateMiner {

    private static final int MAX_DEPTH = 4;
    private static final double SIMILARITY_THRESHOLD = 0.5;
    private static final String VARIABLE_TOKEN = "<*>";

    private final Node root = new Node(0, "ROOT");

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TemplateMiningResult {
        private String template;                    // e.g. "Aug 30 10:32:21 <*> [DENY] proto=TCP src=<*> dst=<*>"
        private List<String> rawTokens;               // original tokens
        private List<String> templateTokens;          // tokens with <*> in place of variables
        private List<Integer> variableIndices;        // indices of variable tokens
        private Map<Integer, String> extractedSlots;  // slot index -> original sample value
        private String regexPattern;                  // synthesized regex capturing variables
    }

    private static class Node {
        final int depth;
        final String token;
        final Map<String, Node> children = new HashMap<>();
        final List<LogCluster> clusters = new ArrayList<>();

        Node(int depth, String token) {
            this.depth = depth;
            this.token = token;
        }
    }

    @Data
    @AllArgsConstructor
    public static class LogCluster {
        private List<String> logTemplateTokens;
        private int clusterSize;

        public String getTemplateString() {
            return String.join(" ", logTemplateTokens);
        }
    }

    /**
     * Mine the structural template of a log message using Drain algorithm.
     */
    public TemplateMiningResult mine(String rawLog) {
        if (rawLog == null || rawLog.isBlank()) {
            return TemplateMiningResult.builder()
                    .template("")
                    .rawTokens(Collections.emptyList())
                    .templateTokens(Collections.emptyList())
                    .variableIndices(Collections.emptyList())
                    .extractedSlots(Collections.emptyMap())
                    .regexPattern("")
                    .build();
        }

        List<String> tokens = tokenize(rawLog);
        LogCluster matchedCluster = treeSearch(tokens);

        List<String> templateTokens;
        if (matchedCluster == null) {
            templateTokens = new ArrayList<>(tokens);
            // Identify dynamic/variable tokens directly (e.g. IPs, numbers, dates, hashes)
            for (int i = 0; i < templateTokens.size(); i++) {
                String t = templateTokens.get(i);
                if (isDynamicToken(t)) {
                    templateTokens.set(i, VARIABLE_TOKEN);
                }
            }
            LogCluster newCluster = new LogCluster(templateTokens, 1);
            treeInsert(tokens, newCluster);
        } else {
            // Merge with existing cluster template
            templateTokens = matchedCluster.getLogTemplateTokens();
            for (int i = 0; i < Math.min(tokens.size(), templateTokens.size()); i++) {
                if (!templateTokens.get(i).equals(tokens.get(i))) {
                    templateTokens.set(i, VARIABLE_TOKEN);
                }
            }
            matchedCluster.setClusterSize(matchedCluster.getClusterSize() + 1);
        }

        List<Integer> varIndices = new ArrayList<>();
        Map<Integer, String> slots = new LinkedHashMap<>();
        StringBuilder regex = new StringBuilder("^");

        for (int i = 0; i < tokens.size(); i++) {
            if (i > 0) regex.append("\\s+");
            String templateTok = i < templateTokens.size() ? templateTokens.get(i) : VARIABLE_TOKEN;
            String rawTok = tokens.get(i);

            if (VARIABLE_TOKEN.equals(templateTok)) {
                varIndices.add(i);
                slots.put(i, rawTok);
                regex.append("(?<token").append(i).append(">\\S+)");
            } else {
                regex.append(Pattern.quote(templateTok));
            }
        }
        regex.append("$");

        return TemplateMiningResult.builder()
                .template(String.join(" ", templateTokens))
                .rawTokens(tokens)
                .templateTokens(templateTokens)
                .variableIndices(varIndices)
                .extractedSlots(slots)
                .regexPattern(regex.toString())
                .build();
    }

    private List<String> tokenize(String log) {
        String[] split = log.trim().split("\\s+");
        return new ArrayList<>(Arrays.asList(split));
    }

    private boolean isDynamicToken(String token) {
        if (token == null || token.isEmpty()) return false;
        // IP Address check (e.g. 192.168.1.5 or with port 192.168.1.5:80 or /443)
        if (token.matches(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*")) return true;
        // Pure number (port, PID, counter)
        if (token.matches("^\\d+$")) return true;
        // Hex / Hash / UUID
        if (token.matches("^[0-9a-fA-F-]{8,}$")) return true;
        // Action words (ALLOW, DENY, BLOCK, DROP, PERMIT, PASS, REJECT, ACCEPT)
        String upper = token.toUpperCase().replaceAll("[\\[\\](),\"';]", "");
        if (upper.equals("ALLOW") || upper.equals("ALLOWED") || upper.equals("PERMIT") ||
            upper.equals("DENY") || upper.equals("DENIED") || upper.equals("BLOCK") ||
            upper.equals("BLOCKED") || upper.equals("DROP") || upper.equals("DROPPED") ||
            upper.equals("REJECT") || upper.equals("ACCEPT") || upper.equals("PASS")) {
            return true;
        }
        // Timestamp / Date tokens
        if (token.matches(".*\\d{2}:\\d{2}:\\d{2}.*") || token.matches(".*\\d{4}-\\d{2}-\\d{2}.*")) return true;
        // Key-Value variable pairs (e.g. user=guest, proto=TCP, src=..., dst=...)
        if (token.contains("=") && token.indexOf('=') > 0 && token.indexOf('=') < token.length() - 1) {
            return true;
        }
        return false;
    }

    private synchronized LogCluster treeSearch(List<String> tokens) {
        int seqLen = tokens.size();
        String lenKey = "LEN_" + seqLen;

        Node lenNode = root.children.get(lenKey);
        if (lenNode == null) {
            return null;
        }

        Node current = lenNode;
        for (int i = 0; i < Math.min(tokens.size(), MAX_DEPTH); i++) {
            String token = tokens.get(i);
            Node next = current.children.get(token);
            if (next == null) {
                next = current.children.get(VARIABLE_TOKEN);
            }
            if (next == null) {
                break;
            }
            current = next;
        }

        return findBestMatch(current.clusters, tokens);
    }

    private synchronized void treeInsert(List<String> tokens, LogCluster cluster) {
        int seqLen = tokens.size();
        String lenKey = "LEN_" + seqLen;

        Node lenNode = root.children.computeIfAbsent(lenKey, k -> new Node(1, lenKey));
        Node current = lenNode;

        for (int i = 0; i < Math.min(tokens.size(), MAX_DEPTH); i++) {
            String token = tokens.get(i);
            if (isDynamicToken(token)) {
                token = VARIABLE_TOKEN;
            }
            final String tok = token;
            final int childDepth = current.depth + 1;
            current = current.children.computeIfAbsent(tok, k -> new Node(childDepth, tok));
        }

        current.clusters.add(cluster);
    }

    private LogCluster findBestMatch(List<LogCluster> clusters, List<String> tokens) {
        LogCluster best = null;
        double maxSim = -1.0;

        for (LogCluster cluster : clusters) {
            List<String> tTokens = cluster.getLogTemplateTokens();
            if (tTokens.size() != tokens.size()) continue;

            int matchCount = 0;
            for (int i = 0; i < tokens.size(); i++) {
                if (VARIABLE_TOKEN.equals(tTokens.get(i)) || tTokens.get(i).equals(tokens.get(i))) {
                    matchCount++;
                }
            }
            double sim = (double) matchCount / tokens.size();
            if (sim >= SIMILARITY_THRESHOLD && sim > maxSim) {
                maxSim = sim;
                best = cluster;
            }
        }
        return best;
    }
}
