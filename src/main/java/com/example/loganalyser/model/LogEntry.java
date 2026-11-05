package com.example.loganalyser.model;

// Import the java.time.MonthDay class to represent the timestamp of the log entry. This is justified as it allows for accurate representation of date and time information, which is needed to accurately log events in the system. A String was not chosen as it would be less accurate and less extensible if more date and time formats were to be added.
import java.time.LocalTime;
import java.time.MonthDay;

public class LogEntry {

    // Declare the fields of the LogEntry class as private and final to ensure that they are immutable and cannot be modified after the object is created. This is justified as it allows for better encapsulation and data integrity, which is needed to ensure that the log entry data is accurate and consistent throughout the application. Using non final fields wasnt justified as it would allow for modification of the log entry data, which could lead to inconsistencies and errors in the application.
    private final EventType eventType;
    private final String sourceIp;
    private final String username;
    private final MonthDay date;
    private final LocalTime time;
    private final String eventDetails;

    // Constructor to create a new LogEntry object with the specified event type, source IP, username, timestamp, and event details. This is justified as it allows for the creation of log entry objects with all the necessary information, which is needed to accurately log events in the system. An empty constructor could not be justified as it would allow for the creation of log entry objects without any information leading to invalid log entries being created.
    public LogEntry(EventType eventType, String sourceIp, String username, MonthDay date, LocalTime time, String eventDetails) {

        // Validate the input parameters to ensure that they are not null or blank, and throw an IllegalArgumentException if they are. 
         if (date == null || time == null) {
            throw new IllegalArgumentException("Date and time cannot be null");
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
        this.date = date;
        this.time = time;
        this.eventDetails = eventDetails;
        
    }

    // Getter methods to retrieve event type
    public EventType getEventType() {
        return eventType;
    }

    // Getter methods to retrieve sourceip
    public String getSourceIp() {
        return sourceIp;
    }

    // Getter methods to retrieve username
    public String getUsername() {
        return username;
    }

    // Getter methods to retrieve date
    public MonthDay getDate() {
        return date;
    }

    // Getter methods to retrieve time
    public LocalTime getTime() {
        return time;
    }

    // Getter methods to retrieve event details
    public String getEventDetails() {
        return eventDetails;
    }
}
