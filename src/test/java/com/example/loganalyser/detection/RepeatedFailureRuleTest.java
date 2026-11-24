package com.example.loganalyser.detection;
import java.time.LocalTime;
import java.time.MonthDay;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.example.loganalyser.config.DetectionConfig;
import com.example.loganalyser.model.Alert;
import com.example.loganalyser.model.EventType;
import com.example.loganalyser.model.LogEntry;



public class RepeatedFailureRuleTest {

    private DetectionConfig detectionConfig;
    private RepeatedFailureRule repeatedFailureRule;
    private final String eventDetails =("Authentication method: password\n" +"Source port: 22\n" +"SSH protocol: ssh2");


    @BeforeEach
    public void setUp() {
        detectionConfig = new DetectionConfig();
        repeatedFailureRule = new RepeatedFailureRule(detectionConfig);
    }

    // Detect five failed logins within the threshold.
    @Test
    public void testDetectRepeatedFailedLoginsAtThreshold() {

        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 2), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 3), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 4), eventDetails));

        List<Alert> alerts = repeatedFailureRule.detect(logEntries);

        assertEquals(1, alerts.size());
        assertEquals(5, alerts.get(0).getFailedAttemptCount());
    }

    // Do not detect an alert below the threshold.
    @Test
    public void testDetectRepeatedFailedLoginsBelowThreshold() {

        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 2), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 3), eventDetails));

        List<Alert> alerts = repeatedFailureRule.detect(logEntries);

        assertTrue(alerts.isEmpty());
    }

    // Detect multiple batches of failed logins above the threshold.
    @Test
    public void testDetectRepeatedFailedLoginsAboveThreshold() {

        List<LogEntry> logEntries = new ArrayList<>();

        for (int i = 0; i < 10; i++) {
            logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, i), eventDetails));
        }

        List<Alert> alerts = repeatedFailureRule.detect(logEntries);

        assertEquals(2, alerts.size());
        assertEquals(5, alerts.get(0).getFailedAttemptCount());
        assertEquals(5, alerts.get(1).getFailedAttemptCount());
    }

    // Do not detect an alert when failures exceed the time window.
    @Test
    public void testDetectRepeatedFailedLoginsOutsideTimeWindow() {

        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 2), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 3), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 6), eventDetails));

        List<Alert> alerts = repeatedFailureRule.detect(logEntries);

        assertTrue(alerts.isEmpty());
    }

    // Count failures from different IP addresses independently.
    @Test
    public void testDetectRepeatedFailedLoginsFromDifferentIps() {

        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.60", "alice", MonthDay.of(11, 20), LocalTime.of(9, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.60", "alice", MonthDay.of(11, 20), LocalTime.of(9, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 2), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.60", "alice", MonthDay.of(11, 20), LocalTime.of(9, 2), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 3), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.60", "alice", MonthDay.of(11, 20), LocalTime.of(9, 3), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 4), eventDetails));

        List<Alert> alerts = repeatedFailureRule.detect(logEntries);

        assertEquals(1, alerts.size());
        assertEquals("192.168.0.50", alerts.get(0).getSourceIp());
    }

    // Count failures from different usernames using the same IP address.
    @Test
    public void testDetectRepeatedFailedLoginsWithDifferentUsernames() {

        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "alice", MonthDay.of(11, 20), LocalTime.of(9, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "alice", MonthDay.of(11, 20), LocalTime.of(9, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "bob", MonthDay.of(11, 20), LocalTime.of(9, 2), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "bob", MonthDay.of(11, 20), LocalTime.of(9, 3), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 4), eventDetails));

        List<Alert> alerts = repeatedFailureRule.detect(logEntries);

        assertEquals(1, alerts.size());
        assertEquals(5, alerts.get(0).getFailedAttemptCount());
        assertEquals("labadmin", alerts.get(0).getUsername());
    }

    // Successful logins should not contribute to the failure threshold.
    @Test
    public void testDetectRepeatedFailedLoginsWithSuccessfulLogin() {

        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_SUCCESS, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 2), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 3), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 4), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 5), eventDetails));

        List<Alert> alerts = repeatedFailureRule.detect(logEntries);

        assertEquals(1, alerts.size());
        assertEquals(5, alerts.get(0).getFailedAttemptCount());
    }

    // Detect repeated failures spanning midnight.
    @Test
    public void testDetectRepeatedFailedLoginsAcrossMidnight() {

        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(23, 58), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(23, 59), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 21), LocalTime.of(0, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 21), LocalTime.of(0, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 21), LocalTime.of(0, 2), eventDetails));

        List<Alert> alerts = repeatedFailureRule.detect(logEntries);

        assertEquals(1, alerts.size());
        assertEquals(5, alerts.get(0).getFailedAttemptCount());
        assertEquals(MonthDay.of(11, 21), alerts.get(0).getDate());
        assertEquals(LocalTime.of(0, 2), alerts.get(0).getTime());
    }

    // Detect repeated failures spanning New Year.
    @Test
    public void testDetectRepeatedFailedLoginsAcrossNewYear() {

        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(12, 31), LocalTime.of(23, 58), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(12, 31), LocalTime.of(23, 59), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(1, 1), LocalTime.of(0, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(1, 1), LocalTime.of(0, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(1, 1), LocalTime.of(0, 2), eventDetails));

        List<Alert> alerts = repeatedFailureRule.detect(logEntries);

        assertEquals(1, alerts.size());
        assertEquals(5, alerts.get(0).getFailedAttemptCount());
        assertEquals(MonthDay.of(1, 1), alerts.get(0).getDate());
        assertEquals(LocalTime.of(0, 2), alerts.get(0).getTime());
    }

    // Accept failures exactly at the five-minute time-window boundary.
    @Test
    public void testDetectRepeatedFailedLoginsAtExactTimeWindowBoundary() {

        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 2), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 3), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 5), eventDetails));

        List<Alert> alerts = repeatedFailureRule.detect(logEntries);

        assertEquals(1, alerts.size());
        assertEquals(5, alerts.get(0).getFailedAttemptCount());
    }

    // Return no alerts when the input list is empty.
    @Test
    public void testDetectWithEmptyLogEntries() {

        List<LogEntry> logEntries = new ArrayList<>();

        List<Alert> alerts = repeatedFailureRule.detect(logEntries);

        assertTrue(alerts.isEmpty());
    }

  
}




































