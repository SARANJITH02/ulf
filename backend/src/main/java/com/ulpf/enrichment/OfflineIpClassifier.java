package com.ulpf.enrichment;

import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.UnknownHostException;

@Component
public class OfflineIpClassifier {

    public boolean isInternal(String ip) {
        if (ip == null || ip.isBlank() || ip.equals("0.0.0.0") || ip.equals("::")) {
            return false;
        }

        try {
            InetAddress addr = InetAddress.getByName(ip.trim());
            if (addr.isSiteLocalAddress() || addr.isLoopbackAddress() || addr.isLinkLocalAddress()) {
                return true;
            }

            byte[] bytes = addr.getAddress();
            if (bytes.length == 4) {
                int first = bytes[0] & 0xFF;
                int second = bytes[1] & 0xFF;

                // 10.0.0.0/8
                if (first == 10) return true;
                // 172.16.0.0/12 (172.16.x.x - 172.31.x.x)
                if (first == 172 && second >= 16 && second <= 31) return true;
                // 192.168.0.0/16
                if (first == 192 && second == 168) return true;
                // 100.64.0.0/10 (Carrier-grade NAT)
                if (first == 100 && second >= 64 && second <= 127) return true;
                // Loopback 127.0.0.0/8
                if (first == 127) return true;
            }
            return false;
        } catch (UnknownHostException e) {
            // Check via regex fallback
            String trimmed = ip.trim();
            if (trimmed.startsWith("10.") || trimmed.startsWith("192.168.") || trimmed.startsWith("127.")) {
                return true;
            }
            if (trimmed.startsWith("172.")) {
                String[] parts = trimmed.split("\\.");
                if (parts.length >= 2) {
                    try {
                        int sec = Integer.parseInt(parts[1]);
                        return sec >= 16 && sec <= 31;
                    } catch (NumberFormatException ignored) {}
                }
            }
            return false;
        }
    }

    public String classifyCategory(String ip) {
        if (ip == null || ip.isBlank()) return "UNKNOWN";
        if (isInternal(ip)) return "PRIVATE_RFC1918";
        return "PUBLIC_INTERNET";
    }
}
