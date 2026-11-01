package com.example.loganalyser.model;

import java.time.LocalDateTime;

public class LogEntry {
    private final EventType eventType;
    private final String sourceIp;
    private final String username;
    private final LocalDateTime timestamp;
    private final String eventDetails;

    public LogEntry(
            EventType eventType,
            String sourceIp,
            String username,
            LocalDateTime timestamp,
            String eventDetails) {

        if (timestamp == null) {
            throw new IllegalArgumentException("Timestamp cannot be null");
        }

        if (eventType == null) {
            throw new IllegalArgumentException("Event type cannot be null");
        }

        if (sourceIp == null || sourceIp.isBlank()) {
            throw new IllegalArgumentException("Source IP cannot be null or blank");
        }

        this.eventType = eventType;
        this.sourceIp = sourceIp;
        this.username = username;
        this.timestamp = timestamp;
        this.eventDetails = eventDetails;
    }

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
