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

// Unit tests for RepeatedFailureRule, covering failure thresholds, time windows, IP and username handling, successful logins and date boundaries.
// Tests the detection of repeated failed SSH logins using controlled log entries and the default detection configuration.
public class RepeatedFailureRuleTest {

    private DetectionConfig detectionConfig;
    private RepeatedFailureRule repeatedFailureRule;
    private final String eventDetails = ("Authentication method: password\n" + "Source port: 22\n" + "SSH protocol: ssh2");

    @BeforeEach
    public void setUp() {
        detectionConfig = new DetectionConfig();
        repeatedFailureRule = new RepeatedFailureRule(detectionConfig);
    }

    // Unit test – Functional and threshold coverage: verifies that five failed logins within the configured time window generate an alert.
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

    // Unit test – Boundary and negative condition coverage: verifies that four failed logins below the threshold do not generate an alert.
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

    // Unit test – Functional and repeated-event coverage: verifies that ten failed logins generate two separate alerts, each containing five attempts.
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

    // Unit test – Time-window and negative condition coverage: verifies that five failed logins spread beyond the configured time window do not generate an alert.
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

    // Unit test – IP address isolation coverage: verifies that failures from different IP addresses are counted independently.
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

    // Unit test – Username handling coverage: verifies that failures from different usernames sharing one IP address contribute to the same failure count.
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

    // Unit test – Event-type filtering coverage: verifies that a successful login does not count towards the failed-login threshold.
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

    // Unit test – Date and time boundary coverage: verifies that five failed logins spanning midnight are detected and that the alert records the final login's date and time.
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

    // Unit test – Date boundary coverage: verifies that five failed logins spanning New Year are detected and that the alert records the final login's date and time.
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

    // Unit test – Time-window boundary coverage: verifies that five failed logins spanning exactly five minutes are accepted by the configured time window.
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

    // Unit test – Edge-case coverage: verifies that an empty list of log entries produces no alerts.
    @Test
    public void testDetectWithEmptyLogEntries() {

        List<LogEntry> logEntries = new ArrayList<>();

        List<Alert> alerts = repeatedFailureRule.detect(logEntries);

        assertTrue(alerts.isEmpty());
    }
}
