package com.ulpf.correlation;

import java.util.*;

/**
 * Deterministic MITRE Enterprise Kill-Chain Tactic Ordering.
 * Defines the standard kill-chain sequence used for narrative progression
 * and horizontal timeline visualization.
 */
public class MitreTacticOrder {

    public static final List<String> ORDERED_TACTICS = List.of(
            "Reconnaissance",
            "Resource Development",
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Exfiltration",
            "Impact"
    );

    private static final Map<String, Integer> TACTIC_RANK_MAP = new HashMap<>();

    static {
        for (int i = 0; i < ORDERED_TACTICS.size(); i++) {
            TACTIC_RANK_MAP.put(normalize(ORDERED_TACTICS.get(i)), i + 1);
        }
    }

    public static int getRank(String tactic) {
        if (tactic == null) return 999;
        return TACTIC_RANK_MAP.getOrDefault(normalize(tactic), 999);
    }

    public static String canonicalize(String tactic) {
        if (tactic == null) return "Unknown Tactic";
        String norm = normalize(tactic);
        for (String canonical : ORDERED_TACTICS) {
            if (normalize(canonical).equals(norm)) {
                return canonical;
            }
        }
        return tactic;
    }

    public static Comparator<String> comparator() {
        return Comparator.comparingInt(MitreTacticOrder::getRank);
    }

    private static String normalize(String s) {
        return s.toLowerCase().replaceAll("[^a-z0-9]", "");
    }
}
