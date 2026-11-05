// package declaration for the LogParser class, which is part of the com.example.loganalyser.parser package. 
package com.example.loganalyser.parser;

// Import the necessary classes from the com.example.loganalyser.model package to represent log entries and parse results. 
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalTime;
import java.time.MonthDay;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

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
            logEntry.contains("Invalid user") ||
            logEntry.contains("Accepted keyboard-interactive"))) {
            return true;
        }
        return false;   
    }

   

    public ParseResult parseLogFile(Path logFilePath) throws IOException {
        
        List<LogEntry> logEntries = new ArrayList<>();
        List<String> malformedEntries = new ArrayList<>();
        List<String> unrecognisedEntries = new ArrayList<>();

        try (BufferedReader reader = Files.newBufferedReader(logFilePath)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue; // Skip empty lines
                }
                if (!isSshLogEntry(line)) {
                    unrecognisedEntries.add(line);
                    continue; // Skip unrecognised entries
                }
        try {
            LogEntry logEntry = new LogEntry(determineEventType(line), extractSourceIp(line), extractUsername(line), extractDate(line), extractTime(line), eventDetails(line));
            logEntries.add(logEntry);
        }

        catch (IllegalArgumentException | DateTimeParseException e) {
            malformedEntries.add(line);
            continue;
        }

    

            }
        }
    
        

        return new ParseResult(logEntries, malformedEntries, unrecognisedEntries);

    }

    public EventType determineEventType(String logEntry) {
        if (logEntry.contains("Accepted")) {
            return EventType.SSH_LOGIN_SUCCESS;
        } 
        else if (logEntry.contains("Failed") || logEntry.contains("Invalid user")) {
            return EventType.SSH_LOGIN_FAILURE;
        } 
        else {
            throw new IllegalArgumentException("Unrecognised log entry: " + logEntry);
        }
    }

    private String extractSourceIp(String logEntry) {
       int fromPosition = logEntry.indexOf("from");
       int portPosition = logEntry.indexOf("port");
       if (fromPosition == -1 || portPosition == -1) {
           throw new IllegalArgumentException("Could not locate source IP");
       }
       else {
        
           String sourceIp = logEntry.substring(fromPosition + 5, portPosition - 1);
           if (sourceIp.isBlank()) {
               throw new IllegalArgumentException("Could not locate source IP");
           }
           return sourceIp;
       }
       
    }

    private MonthDay extractDate(String logEntry) {
       String timestamp = logEntry.substring(0, 15);
         if (timestamp.isBlank()) {
              throw new IllegalArgumentException("Could not locate timestamp");
         }

        String month = timestamp.substring(0, 3);
        String day = timestamp.substring(4, 6);
        DateTimeFormatter dateFormatter = DateTimeFormatter.ofPattern("MMM-dd", Locale.ENGLISH);
        MonthDay logDate = MonthDay.parse(month + "-" + day, DateTimeFormatter.ofPattern("MMM-dd", Locale.ENGLISH));
        return logDate;

    }

    private LocalTime extractTime(String logEntry) {
        String timestamp = logEntry.substring(0, 15);
        if (timestamp.isBlank()) {
            throw new IllegalArgumentException("Could not locate timestamp");
        }

        String time = timestamp.substring(7, 15);
        LocalTime logTime = LocalTime.parse(time);
        return logTime;
    }

    private String extractUsername(String logEntry) {
        if (logEntry == null || logEntry.isBlank()) {
            throw new IllegalArgumentException("Log entry cannot be null or blank");
        }   
        int fromPosition = logEntry.indexOf("from");

        if (fromPosition == -1) {
            throw new IllegalArgumentException("Could not locate username");
        }

        int usernameEnd = logEntry.lastIndexOf(" ", fromPosition - 1);

        if (usernameEnd == -1) {
            throw new IllegalArgumentException("Could not locate username");
        }

        int usernameStart = logEntry.lastIndexOf(" ", usernameEnd - 1);

        if (usernameStart == -1 || usernameStart + 1 >= usernameEnd) {
            throw new IllegalArgumentException("Could not extract username");
        }

        String username = logEntry.substring(usernameStart + 1, usernameEnd);
        return username;
        }

    private String extractAuthenticationMethod(String logEntry) {
        if (logEntry == null || logEntry.isBlank()) {
            throw new IllegalArgumentException("Log entry cannot be null or blank");
        }
        int failedPosition = logEntry.indexOf("Failed");
        int acceptedPosition = logEntry.indexOf("Accepted");
        int forPosition = logEntry.indexOf("for");
        String authenticationMethod = "";
        if (failedPosition == -1 && acceptedPosition == -1) {
            throw new IllegalArgumentException("Log entry does not contain a recognised authentication result");
        }
            
        if (logEntry.contains("Failed")) {
            authenticationMethod = logEntry.substring(failedPosition+7, forPosition-1);
        }

        else if (logEntry.contains("Accepted")) {
            authenticationMethod = logEntry.substring(acceptedPosition+9, forPosition-1);
        }
        if (authenticationMethod.isBlank()) {
            throw new IllegalArgumentException("Authentication method cannot be blank");
        }

        return authenticationMethod;
    }

    private String extractSourcePort(String logEntry) {
        int portPosition = logEntry.indexOf("port");
        String sourcePort = "";

        int portStart = portPosition+5;
        int portEnd = logEntry.indexOf(" ", portPosition+5);
        if (portStart == -1 || portEnd == -1) {
            throw new IllegalArgumentException("Could not extract source port");
        }
        if (portStart == portEnd) {
            throw new IllegalArgumentException("Could not extract source port");
        }

        sourcePort = logEntry.substring(portStart, portEnd);

        return sourcePort;
    }

    private String extractSshProtocol(String logEntry) {
        int finalSpace = logEntry.lastIndexOf(" ");
        if (finalSpace == -1) {
            throw new IllegalArgumentException("Could not extract SSH protocol");
        }
        String sshProtocol = logEntry.substring(finalSpace +1);
        if (sshProtocol.isBlank()) {
            throw new IllegalArgumentException("Could not extract SSH protocol");
        }
        return sshProtocol;
    }

    private String eventDetails(String logEntry) {
        String authenticationMethod = extractAuthenticationMethod(logEntry);
        String sourcePort = extractSourcePort(logEntry);
        String sshProtocol = extractSshProtocol(logEntry);
        String eventDetails = ("Authentication method: " +authenticationMethod + ", Source port: " +sourcePort + ", SSH protocol: " +sshProtocol);

        return eventDetails;
    }



}