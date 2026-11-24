
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

public class SuccessAfterRepeatedFailureRuleTest {

    private DetectionConfig detectionConfig;
    private SuccessAfterRepeatedFailureRule successAfterRepeatedFailureRule;

    private final String eventDetails =( "Authentication method: password\n" + "Source port: 22\n" + "SSH protocol: ssh2");

    @BeforeEach
    public void setUp() {
        detectionConfig = new DetectionConfig();
        successAfterRepeatedFailureRule = new SuccessAfterRepeatedFailureRule(detectionConfig);
    }

    // Detect a successful login after five failed attempts.
    @Test
    public void testDetectSuccessfulLoginAfterFailureThreshold() {

        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 2), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 3), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 4), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_SUCCESS, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 5), eventDetails));

        List<Alert> alerts = successAfterRepeatedFailureRule.detect(logEntries);

        assertEquals(1, alerts.size());
        assertEquals(5, alerts.get(0).getFailedAttemptCount());
    }

    // Do not detect a successful login below the failure threshold.
    @Test
    public void testDetectSuccessfulLoginBelowFailureThreshold() {

        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 2), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 3), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_SUCCESS, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 4), eventDetails));

        List<Alert> alerts = successAfterRepeatedFailureRule.detect(logEntries);

        assertTrue(alerts.isEmpty());
    }

    // Detect a successful login after more than five failed attempts.
    @Test
    public void testDetectSuccessfulLoginAboveFailureThreshold() {

        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 2), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 3), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 4), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 5), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 5), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_SUCCESS, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 5), eventDetails));

        List<Alert> alerts = successAfterRepeatedFailureRule.detect(logEntries);

        assertEquals(1, alerts.size());
        assertEquals(7, alerts.get(0).getFailedAttemptCount());
    }

    // Do not detect a successful login outside the time window.
    @Test
    public void testDetectSuccessfulLoginOutsideTimeWindow() {

        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 2), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 3), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 4), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_SUCCESS, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 6), eventDetails));

        List<Alert> alerts = successAfterRepeatedFailureRule.detect(logEntries);

        assertTrue(alerts.isEmpty());
    }

    // Count failed attempts from different IP addresses independently.
    @Test
    public void testDetectSuccessfulLoginFromDifferentIps() {

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
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_SUCCESS, "192.168.0.60", "alice", MonthDay.of(11, 20), LocalTime.of(9, 5), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_SUCCESS, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 5), eventDetails));

        List<Alert> alerts = successAfterRepeatedFailureRule.detect(logEntries);

        assertEquals(1, alerts.size());
        assertEquals("192.168.0.50", alerts.get(0).getSourceIp());
    }

    //Reset the failure counter after a successful login.
    @Test
    public void testDetectSuccessfulLoginResetsFailureCounter() {

        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 2), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 3), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 4), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_SUCCESS, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 5), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 6), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 7), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 8), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 9), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_SUCCESS, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 10), eventDetails));

        List<Alert> alerts = successAfterRepeatedFailureRule.detect(logEntries);

        assertEquals(1, alerts.size());
        assertEquals(5, alerts.get(0).getFailedAttemptCount());
    }

    // Generate separate alerts for separate qualifying failure groups.
    @Test
    public void testDetectMultipleSuccessfulLoginsAfterFailures() {

        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 2), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 3), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 4), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_SUCCESS, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 5), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 6), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 7), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 8), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 9), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 10), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_SUCCESS, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 11), eventDetails));

        List<Alert> alerts = successAfterRepeatedFailureRule.detect(logEntries);

        assertEquals(2, alerts.size());
        assertEquals(5, alerts.get(0).getFailedAttemptCount());
        assertEquals(5, alerts.get(1).getFailedAttemptCount());
    }

    // Detect failed logins over midnight followed by a successful login.
    @Test
    public void testDetectSuccessfulLoginAcrossMidnight() {

        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(23, 58), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(23, 59), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 21), LocalTime.of(0, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 21), LocalTime.of(0, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 21), LocalTime.of(0, 2), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_SUCCESS, "192.168.0.50", "labadmin", MonthDay.of(11, 21), LocalTime.of(0, 3), eventDetails));

        List<Alert> alerts = successAfterRepeatedFailureRule.detect(logEntries);

        assertEquals(1, alerts.size());
        assertEquals(5, alerts.get(0).getFailedAttemptCount());
        assertEquals(MonthDay.of(11, 21), alerts.get(0).getDate());
        assertEquals(LocalTime.of(0, 3), alerts.get(0).getTime());
    }

    // Detect failed logins over New Year followed by a successful login.
    @Test
    public void testDetectSuccessfulLoginAcrossNewYear() {

        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(12, 31), LocalTime.of(23, 58), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(12, 31), LocalTime.of(23, 59), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(1, 1), LocalTime.of(0, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(1, 1), LocalTime.of(0, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(1, 1), LocalTime.of(0, 2), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_SUCCESS, "192.168.0.50", "labadmin", MonthDay.of(1, 1), LocalTime.of(0, 3), eventDetails));

        List<Alert> alerts = successAfterRepeatedFailureRule.detect(logEntries);

        assertEquals(1, alerts.size());
        assertEquals(5, alerts.get(0).getFailedAttemptCount());
        assertEquals(MonthDay.of(1, 1), alerts.get(0).getDate());
        assertEquals(LocalTime.of(0, 3), alerts.get(0).getTime());
    }

    // Accept a successful login exactly at the five minute boundary.
    @Test
    public void testDetectSuccessfulLoginAtExactTimeWindowBoundary() {

        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 2), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 3), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 4), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_SUCCESS, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 5), eventDetails));

        List<Alert> alerts = successAfterRepeatedFailureRule.detect(logEntries);

        assertEquals(1, alerts.size());
        assertEquals(5, alerts.get(0).getFailedAttemptCount());
    }

    // Return no alerts when the input list is empty.
    @Test
    public void testDetectWithEmptyLogEntries() {

        List<LogEntry> logEntries = new ArrayList<>();

        List<Alert> alerts = successAfterRepeatedFailureRule.detect(logEntries);

        assertTrue(alerts.isEmpty());
    }

    
}
