package com.ulpf.normalization;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class ReverseExporter {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final EcsAliasMap ecsAliasMap;

    /**
     * Export normalized OCSF event to standard ArcSight CEF wire string
     */
    public String toCefWire(OcsfSchema ocsf) {
        if (ocsf == null) return "";

        String vendor = ocsf.getObserver() != null && ocsf.getObserver().getVendor() != null ? ocsf.getObserver().getVendor() : "ULPF";
        String product = ocsf.getObserver() != null && ocsf.getObserver().getProduct() != null ? ocsf.getObserver().getProduct() : "Gateway";
        String version = ocsf.getObserver() != null && ocsf.getObserver().getVersion() != null ? ocsf.getObserver().getVersion() : "1.0";
        String classId = ocsf.getEvent() != null && ocsf.getEvent().getType() != null ? ocsf.getEvent().getType() : "traffic";
        String name = ocsf.getEvent() != null && ocsf.getEvent().getMessage() != null ? ocsf.getEvent().getMessage() : "Security Event";
        int severity = ocsf.getEvent() != null && ocsf.getEvent().getSeverityId() != null ? ocsf.getEvent().getSeverityId() : 1;

        StringBuilder sb = new StringBuilder();
        sb.append("CEF:0|").append(sanitizePipe(vendor)).append("|")
          .append(sanitizePipe(product)).append("|")
          .append(sanitizePipe(version)).append("|")
          .append(sanitizePipe(classId)).append("|")
          .append(sanitizePipe(name)).append("|")
          .append(severity).append("|");

        // Extensions
        if (ocsf.getSource() != null && ocsf.getSource().getIp() != null) {
            sb.append("src=").append(ocsf.getSource().getIp()).append(" ");
        }
        if (ocsf.getSource() != null && ocsf.getSource().getPort() != null) {
            sb.append("spt=").append(ocsf.getSource().getPort()).append(" ");
        }
        if (ocsf.getSource() != null && ocsf.getSource().getUser() != null) {
            sb.append("suser=").append(ocsf.getSource().getUser()).append(" ");
        }
        if (ocsf.getDestination() != null && ocsf.getDestination().getIp() != null) {
            sb.append("dst=").append(ocsf.getDestination().getIp()).append(" ");
        }
        if (ocsf.getDestination() != null && ocsf.getDestination().getPort() != null) {
            sb.append("dpt=").append(ocsf.getDestination().getPort()).append(" ");
        }
        if (ocsf.getNetwork() != null && ocsf.getNetwork().getProtocol() != null) {
            sb.append("proto=").append(ocsf.getNetwork().getProtocol()).append(" ");
        }
        if (ocsf.getEvent() != null && ocsf.getEvent().getAction() != null) {
            sb.append("act=").append(ocsf.getEvent().getAction()).append(" ");
        }
        if (ocsf.getRawHashSha256() != null) {
            sb.append("rawHash=").append(ocsf.getRawHashSha256()).append(" ");
        }
        if (ocsf.getEventId() != null) {
            sb.append("externalId=").append(ocsf.getEventId()).append(" ");
        }

        return sb.toString().trim();
    }

    /**
     * Export normalized OCSF event to standard IBM QRadar LEEF 1.0 wire string (tab-delimited)
     */
    public String toLeefWire(OcsfSchema ocsf) {
        if (ocsf == null) return "";

        String vendor = ocsf.getObserver() != null && ocsf.getObserver().getVendor() != null ? ocsf.getObserver().getVendor() : "ULPF";
        String product = ocsf.getObserver() != null && ocsf.getObserver().getProduct() != null ? ocsf.getObserver().getProduct() : "Gateway";
        String version = ocsf.getObserver() != null && ocsf.getObserver().getVersion() != null ? ocsf.getObserver().getVersion() : "1.0";
        String eventId = ocsf.getEvent() != null && ocsf.getEvent().getType() != null ? ocsf.getEvent().getType() : "SecEvent";

        StringBuilder sb = new StringBuilder();
        sb.append("LEEF:1.0|").append(sanitizePipe(vendor)).append("|")
          .append(sanitizePipe(product)).append("|")
          .append(sanitizePipe(version)).append("|")
          .append(sanitizePipe(eventId)).append("|");

        if (ocsf.getSource() != null && ocsf.getSource().getIp() != null) {
            sb.append("src=").append(ocsf.getSource().getIp()).append("\t");
        }
        if (ocsf.getSource() != null && ocsf.getSource().getPort() != null) {
            sb.append("srcPort=").append(ocsf.getSource().getPort()).append("\t");
        }
        if (ocsf.getSource() != null && ocsf.getSource().getUser() != null) {
            sb.append("usrName=").append(ocsf.getSource().getUser()).append("\t");
        }
        if (ocsf.getDestination() != null && ocsf.getDestination().getIp() != null) {
            sb.append("dst=").append(ocsf.getDestination().getIp()).append("\t");
        }
        if (ocsf.getDestination() != null && ocsf.getDestination().getPort() != null) {
            sb.append("dstPort=").append(ocsf.getDestination().getPort()).append("\t");
        }
        if (ocsf.getNetwork() != null && ocsf.getNetwork().getProtocol() != null) {
            sb.append("proto=").append(ocsf.getNetwork().getProtocol()).append("\t");
        }
        if (ocsf.getEvent() != null && ocsf.getEvent().getAction() != null) {
            sb.append("action=").append(ocsf.getEvent().getAction()).append("\t");
        }
        if (ocsf.getEventId() != null) {
            sb.append("eventId=").append(ocsf.getEventId()).append("\t");
        }

        return sb.toString().trim();
    }

    /**
     * Export normalized OCSF event to Elastic Common Schema (ECS) JSON document
     */
    public ObjectNode toEcsJson(OcsfSchema ocsf) {
        ObjectNode root = objectMapper.createObjectNode();
        if (ocsf == null) return root;

        root.put("@timestamp", ocsf.getTimestampUtc());

        // Event
        ObjectNode ecsEvent = root.putObject("event");
        if (ocsf.getEventId() != null) ecsEvent.put("id", ocsf.getEventId());
        if (ocsf.getEvent() != null) {
            if (ocsf.getEvent().getCategory() != null) ecsEvent.put("category", ocsf.getEvent().getCategory());
            if (ocsf.getEvent().getType() != null) ecsEvent.put("type", ocsf.getEvent().getType());
            if (ocsf.getEvent().getAction() != null) ecsEvent.put("action", ocsf.getEvent().getAction());
            if (ocsf.getEvent().getSeverity() != null) ecsEvent.put("severity", ocsf.getEvent().getSeverity());
            if (ocsf.getEvent().getMessage() != null) ecsEvent.put("reason", ocsf.getEvent().getMessage());
        }
        if (ocsf.getRaw() != null && ocsf.getRaw().getMessage() != null) {
            ecsEvent.put("original", ocsf.getRaw().getMessage());
        }
        if (ocsf.getRawHashSha256() != null) {
            ObjectNode hashNode = ecsEvent.putObject("hash");
            hashNode.put("sha256", ocsf.getRawHashSha256());
        }

        // Source
        if (ocsf.getSource() != null) {
            ObjectNode src = root.putObject("source");
            if (ocsf.getSource().getIp() != null) src.put("ip", ocsf.getSource().getIp());
            if (ocsf.getSource().getPort() != null) src.put("port", ocsf.getSource().getPort());
            if (ocsf.getSource().getHostname() != null) src.put("domain", ocsf.getSource().getHostname());
            if (ocsf.getSource().getUser() != null) {
                ObjectNode user = src.putObject("user");
                user.put("name", ocsf.getSource().getUser());
            }
        }

        // Destination
        if (ocsf.getDestination() != null) {
            ObjectNode dst = root.putObject("destination");
            if (ocsf.getDestination().getIp() != null) dst.put("ip", ocsf.getDestination().getIp());
            if (ocsf.getDestination().getPort() != null) dst.put("port", ocsf.getDestination().getPort());
            if (ocsf.getDestination().getHostname() != null) dst.put("domain", ocsf.getDestination().getHostname());
        }

        // Network
        if (ocsf.getNetwork() != null) {
            ObjectNode net = root.putObject("network");
            if (ocsf.getNetwork().getProtocol() != null) net.put("transport", ocsf.getNetwork().getProtocol());
            if (ocsf.getNetwork().getDirection() != null) net.put("direction", ocsf.getNetwork().getDirection());
        }

        // Observer
        if (ocsf.getObserver() != null) {
            ObjectNode obs = root.putObject("observer");
            if (ocsf.getObserver().getVendor() != null) obs.put("vendor", ocsf.getObserver().getVendor());
            if (ocsf.getObserver().getProduct() != null) obs.put("product", ocsf.getObserver().getProduct());
            if (ocsf.getObserver().getHostname() != null) obs.put("hostname", ocsf.getObserver().getHostname());
        }

        // Threat / MITRE
        if (ocsf.getThreat() != null && ocsf.getThreat().getMitreTechniqueId() != null) {
            ObjectNode threatNode = root.putObject("threat");
            ObjectNode techNode = threatNode.putObject("technique");
            techNode.put("id", ocsf.getThreat().getMitreTechniqueId());
            if (ocsf.getThreat().getMitreTechniqueName() != null) techNode.put("name", ocsf.getThreat().getMitreTechniqueName());
            if (ocsf.getThreat().getMitreTactic() != null) {
                ObjectNode tacticNode = threatNode.putObject("tactic");
                tacticNode.put("name", ocsf.getThreat().getMitreTactic());
            }
        }

        return root;
    }

    private String sanitizePipe(String s) {
        if (s == null) return "";
        return s.replace("|", "\\|").replace("\\", "\\\\");
    }
}
