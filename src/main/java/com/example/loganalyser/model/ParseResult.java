// package declaration for the ParseResult class, which is part of the com.example.loganalyser.model package. 
package com.example.loganalyser.model;

// Import the java.util.ArrayList and java.util.List classes to represent a list of log entries. 
import java.util.ArrayList;
import java.util.List;

public class ParseResult {

    // Declare the fields of the ParseResult class as private and final to ensure that they are immutable and cannot be modified after the object is created. This is justified as it allows for strong encapsulation and data integrity, which is needed to ensure that the parse result data is accurate and consistent throughout the application. Using non final fields wasnt justified as it would allow for modification of the parse result data, which could lead to inconsistencies and errors in the application.
    private final List<LogEntry> logEntries;
    private final List<String> malformedEntries;
    private final List<String> unrecognisedEntries;
    private final List<String> otherSSHEntries;

    // Constructor to create a new ParseResult object with the specified list of log entries, list of malformed entries, and list of unrecognised entries.
    public ParseResult(List<LogEntry> logEntries, List<String> malformedEntries, List<String> unrecognisedEntries, List<String> otherSSHEntries) {
        
        // Validate the input parameters to ensure that they are not null or negative, and throw an IllegalArgumentException if they are. This is justified as it ensures that there is robust input validation and error handling in place, which is needed to prevent invalid data from being processed and to maintain the integrity of the parse result data.
        if (logEntries == null) {
            throw new IllegalArgumentException("Log entries list cannot be null");
        }
        if (malformedEntries == null || unrecognisedEntries == null || otherSSHEntries == null) {
            throw new IllegalArgumentException("Entry lists cannot be null");
        }

        // Assign the input parameters to the corresponding fields of the ParseResult object.
        // Log entries are copied into a new ArrayList to ensure that the internal list is not affected by external modifications, which is needed to maintain the integrity of the parse result data.
        this.logEntries = new ArrayList<>(logEntries);
        this.malformedEntries = new ArrayList<>(malformedEntries);
        this.unrecognisedEntries = unrecognisedEntries;
        this.otherSSHEntries = otherSSHEntries;
    }

    // Getter methods to retrieve log entries
    // Log entries are returned as a new ArrayList to ensure that the internal list is not affected by external modifications, which is needed to maintain the integrity of the parse result data.
    public List<LogEntry> getLogEntries() {
        return new ArrayList<>(logEntries);
    }

    // Getter methods to retrieve malformed entries
    // Malformed entries are returned as a new ArrayList to ensure that the internal list is not affected by external modifications, which is needed to maintain the integrity of the parse result data.
    public List<String> getMalformedEntries() {
        return new ArrayList<> (malformedEntries);
    }

    // Getter methods to retrieve unrecognised entries
    // Unrecognised entries are returned as a new ArrayList to ensure that the internal list is not affected by external modifications, which is needed to maintain the integrity of the parse result data.
    public List<String> getUnrecognisedEntries() {
        return new ArrayList<>(unrecognisedEntries);
    }

    // Getter methods to retrieve other SSH entries
    // Other SSH entries are returned as a new ArrayList to ensure that the internal list is not affected by external modifications, which is needed to maintain the integrity of the parse result data.
    public List<String> getOtherSSHEntries() {
        return new ArrayList<>(otherSSHEntries);
    }
}
