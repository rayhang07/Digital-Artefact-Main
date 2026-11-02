// package declaration for the LogParser class, which is part of the com.example.loganalyser.parser package. 
package com.example.loganalyser.parser;

// Import the necessary classes from the com.example.loganalyser.model package to represent log entries and parse results. 
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import com.example.loganalyser.model.EventType;
import com.example.loganalyser.model.LogEntry;
import com.example.loganalyser.model.ParseResult;

public class LogParser {
    
    public boolean isSshLogEntry(String logEntry) {
        if (logEntry == null || logEntry.isBlank()) {
            return false;
        }
        if (logEntry.contains("sshd") &&
            (logEntry.contains("Failed password") ||
            logEntry.contains("Accepted password") ||
            logEntry.contains("Failed publickey") ||
            logEntry.contains("Accepted publickey") ||
            logEntry.contains("Failed keyboard-interactive") ||
            logEntry.contains("Accepted keyboard-interactive"))) {
            return true;
        }
        return false;   
    }

    public ParseResult parseLogFile(Path logFilePath) throws IOException {
        
        List<LogEntry> logEntries = new ArrayList<>();
        int malformedEntriesCount = 0;
        int unrecognisedEntriesCount = 0;

        try (BufferedReader reader = Files.newBufferedReader(logFilePath)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue; // Skip empty lines
                }
                if (!isSshLogEntry(line)) {
                    unrecognisedEntriesCount++;
                    continue; // Skip unrecognised entries
                }



            }
        }

        return new ParseResult(logEntries, malformedEntriesCount, unrecognisedEntriesCount);

    }

    public EventType determineEventType(String logEntry) {
        if (logEntry.contains("Accepted")) {
            return EventType.SSH_LOGIN_SUCCESS;
        } 
        else if (logEntry.contains("Failed")) {
            return EventType.SSH_LOGIN_FAILURE;
        } 
        else {
            throw new IllegalArgumentException("Unrecognised log entry: " + logEntry);
        }
    }

    private String extractSourceIp(String logEntry) {
       
       return logEntry;
    }

    private String extractUsername(String logEntry) {
        if (logEntry == null || logEntry.isBlank()) {
            throw new IllegalArgumentException("Log entry cannot be null or blank");
        }   
        int fromPosition = logEntry.indexOf("from");
        if (fromPosition == -1) {
            throw new IllegalArgumentException("Could not locate username");
        }
        else {
        int usernameStart = logEntry.lastIndexOf(" ", fromPosition - 1);
        if (usernameStart == -1) {
            throw new IllegalArgumentException("Could not locate username");
        }
        String username = logEntry.substring(usernameStart + 1, fromPosition - 1);
        if (username.isBlank()) {
            throw new IllegalArgumentException("Could not locate username");
        }
        return username;
        }
    }
}

