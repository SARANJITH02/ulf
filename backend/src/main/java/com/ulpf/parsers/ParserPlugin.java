package com.ulpf.parsers;

import com.ulpf.detection.LogFormat;

public interface ParserPlugin {
    String getName();
    String getDisplayName();
    String getVersion();
    String getFormatType();
    boolean canParse(String rawMessage, LogFormat detectedFormat);
    ParsedLogResult parse(String rawMessage);
    boolean isActive();
    void setActive(boolean active);
}
