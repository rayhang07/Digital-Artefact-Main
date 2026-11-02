package com.example.loganalyser.model;

// Import the java.time.LocalDateTime class to represent the timestamp of the log entry. This is justified as it allows for accurate representation of date and time information, which is needed to accurately log events in the system. A String was not chosen as it would be less accurate and less extensible if more date and time formats were to be added.
import java.time.LocalDateTime;

public class LogEntry {

    // Declare the fields of the LogEntry class as private and final to ensure that they are immutable and cannot be modified after the object is created. This is justified as it allows for better encapsulation and data integrity, which is needed to ensure that the log entry data is accurate and consistent throughout the application. Using non final fields wasnt justified as it would allow for modification of the log entry data, which could lead to inconsistencies and errors in the application.
    private final EventType eventType;
    private final String sourceIp;
    private final String username;
    private final LocalDateTime timestamp;
    private final String eventDetails;

    // Constructor to create a new LogEntry object with the specified event type, source IP, username, timestamp, and event details. This is justified as it allows for the creation of log entry objects with all the necessary information, which is needed to accurately log events in the system. An empty constructor could not be justified as it would allow for the creation of log entry objects without any information leading to invalid log entries being created.
    public LogEntry(EventType eventType, String sourceIp, String username, LocalDateTime timestamp, String eventDetails) {

        // Validate the input parameters to ensure that they are not null or blank, and throw an IllegalArgumentException if they are. 
         if (timestamp == null) {
            throw new IllegalArgumentException("Timestamp cannot be null");
        }

        // Validate the input parameters to ensure that they are not null or blank, and throw an IllegalArgumentException if they are.
        if (eventType == null) {
            throw new IllegalArgumentException("Event type cannot be null");
        }

        // Validate the input parameters to ensure that they are not null or blank, and throw an IllegalArgumentException if they are.
        if (sourceIp == null || sourceIp.isBlank()) {
            throw new IllegalArgumentException("Source IP cannot be null or blank");
        }

        // Assign the input parameters to the corresponding fields of the LogEntry object. This is justified as it allows for the creation of log entry objects with all the necessary information, which is needed to accurately log events in the system.
        this.eventType = eventType;
        this.sourceIp = sourceIp;
        this.username = username;
        this.timestamp = timestamp;
        this.eventDetails = eventDetails;
        
    }

    // Getter methods to retrieve values of the fields set
    public EventType getEventType() {
        return eventType;
    }

    
    public String getSourceIp() {
        return sourceIp;
    }

    public String getUsername() {
        return username;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public String getEventDetails() {
        return eventDetails;
    }
}
