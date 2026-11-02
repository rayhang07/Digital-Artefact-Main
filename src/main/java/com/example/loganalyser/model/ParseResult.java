// package declaration for the ParseResult class, which is part of the com.example.loganalyser.model package. 
package com.example.loganalyser.model;

// Import the java.util.ArrayList and java.util.List classes to represent a list of log entries. 
import java.util.ArrayList;
import java.util.List;

public class ParseResult {

    // Declare the fields of the ParseResult class as private and final to ensure that they are immutable and cannot be modified after the object is created. This is justified as it allows for strong encapsulation and data integrity, which is needed to ensure that the parse result data is accurate and consistent throughout the application. Using non final fields wasnt justified as it would allow for modification of the parse result data, which could lead to inconsistencies and errors in the application.
    private final List<LogEntry> logEntries;
    private final int malformedEntriesCount;
    private final int unrecognisedEntriesCount;

    // Constructor to create a new ParseResult object with the specified list of log entries, count of malformed entries, and count of unrecognised entries.
    public ParseResult(List<LogEntry> logEntries, int malformedEntriesCount, int unrecognisedEntriesCount) {
        
        // Validate the input parameters to ensure that they are not null or negative, and throw an IllegalArgumentException if they are. This is justified as it ensures that there is robust input validation and error handling in place, which is needed to prevent invalid data from being processed and to maintain the integrity of the parse result data.
        if (logEntries == null) {
            throw new IllegalArgumentException("Log entries list cannot be null");
        }
        if (malformedEntriesCount < 0 || unrecognisedEntriesCount < 0) {
            throw new IllegalArgumentException("Entry counts cannot be negative");
        }

        // Assign the input parameters to the corresponding fields of the ParseResult object.
        // Log entries are copied into a new ArrayList to ensure that the internal list is not affected by external modifications, which is needed to maintain the integrity of the parse result data.
        this.logEntries = new ArrayList<>(logEntries);
        this.malformedEntriesCount = malformedEntriesCount;
        this.unrecognisedEntriesCount = unrecognisedEntriesCount;
    }

    // Getter methods to retrieve values of the fields set.
    // Log entries are returned as a new ArrayList to ensure that the internal list is not affected by external modifications, which is needed to maintain the integrity of the parse result data.
    public List<LogEntry> getLogEntries() {
        return new ArrayList<>(logEntries);
    }

    public int getMalformedEntriesCount() {
        return malformedEntriesCount;
    }

    public int getUnrecognisedEntriesCount() {
        return unrecognisedEntriesCount;
    }
}
