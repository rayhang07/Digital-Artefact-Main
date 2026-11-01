package com.example.loganalyser.parser;

public class LogParser {

    public boolean isSshLogEntry(String logEntry) {

        if (logEntry == null || logEntry.isBlank()) {
            return false;
        }

        if (!logEntry.contains("sshd")) {
            return false;
        }

        return logEntry.contains("Failed password")
                || logEntry.contains("Accepted password")
                || logEntry.contains("Failed publickey")
                || logEntry.contains("Accepted publickey")
                || logEntry.contains("Failed keyboard-interactive")
                || logEntry.contains("Accepted keyboard-interactive");
    }
}


