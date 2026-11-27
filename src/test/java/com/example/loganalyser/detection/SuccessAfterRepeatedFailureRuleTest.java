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

// Unit tests for SuccessAfterRepeatedFailureRule, covering failure thresholds, time windows, IP address isolation, counter resets and date boundaries.
// Tests the detection of successful SSH logins following repeated failed attempts using controlled log entries and the default detection configuration.
public class SuccessAfterRepeatedFailureRuleTest {

    private DetectionConfig detectionConfig;
    private SuccessAfterRepeatedFailureRule successAfterRepeatedFailureRule;

    private final String eventDetails = ("Authentication method: password\n" + "Source port: 22\n" + "SSH protocol: ssh2");

    @BeforeEach
    public void setUp() {
        detectionConfig = new DetectionConfig();
        successAfterRepeatedFailureRule = new SuccessAfterRepeatedFailureRule(detectionConfig);
    }

    // Unit test – Functional and threshold coverage: verifies that a successful login after five failed attempts generates an alert.
    @Test
    public void testDetectSuccessfulLoginAtFailureThreshold() {

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

    // Unit test – Boundary and negative condition coverage: verifies that a successful login after fewer than five failed attempts generates no alert.
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

    // Unit test – Threshold coverage: verifies that more than five failed attempts followed by a successful login generate one alert containing all seven failures.
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

    // Unit test – Time-window and negative condition coverage: verifies that a successful login outside the configured time window generates no alert.
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

    // Unit test – IP address isolation: verifies that failures from different IP addresses are counted independently when evaluating a successful login.
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

    // Unit test – State and reset behaviour: verifies that a successful login resets the failure counter before subsequent failed attempts.
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

    // Unit test – Multiple-event coverage: verifies that separate groups of qualifying failed attempts followed by successful logins generate separate alerts.
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

    // Unit test – Date and time boundary coverage: verifies that failed attempts spanning midnight are detected when followed by a successful login.
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

    // Unit test – Date boundary coverage: verifies that failed attempts spanning New Year are detected when followed by a successful login.
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

    // Unit test – Time-window boundary coverage: verifies that a successful login exactly five minutes after the first failure is accepted.
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

    // Unit test – Edge-case coverage: verifies that an empty log-entry list produces no alerts.
    @Test
    public void testDetectWithEmptyLogEntries() {

        List<LogEntry> logEntries = new ArrayList<>();

        List<Alert> alerts = successAfterRepeatedFailureRule.detect(logEntries);

        assertTrue(alerts.isEmpty());
    }

}
