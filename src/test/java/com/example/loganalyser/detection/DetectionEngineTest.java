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
import com.example.loganalyser.model.DetectionRuleType;
import com.example.loganalyser.model.EventType;
import com.example.loganalyser.model.LogEntry;

// Unit tests for DetectionEngine, covering rule initialisation, empty and non-matching inputs, alert generation and custom detection thresholds.
// Tests how the engine coordinates its detection rules against log entries using default and custom configurations.
public class DetectionEngineTest {

    private DetectionEngine detectionEngine;
    private DetectionConfig detectionConfig;
    private final String eventDetails = ("Authentication method: password\n" + "Source port: 22\n" + "SSH protocol: ssh2");

    @BeforeEach
    public void setUp() {
        detectionConfig = new DetectionConfig(5, 5);
        detectionEngine = new DetectionEngine(detectionConfig);

    }

    // Unit test – Initialisation and configuration coverage: verifies that the detection engine initialises with both expected detection rules in the correct order.
    @Test
    public void testDetectionEngineInitialisesWithDefaultRules() {
        List<DetectionRule> rules = detectionEngine.getDetectionRules();
        assertEquals(2, rules.size());
        assertTrue(DetectionRuleType.REPEATED_FAILED_SSH_LOGINS == rules.get(0).getRuleType() && DetectionRuleType.SUCCESSFUL_LOGIN_AFTER_FAILURES == rules.get(1).getRuleType());
    }

    // Unit test – Edge-case coverage: verifies that an empty list of log entries produces no alerts.
    @Test
    public void testDetectWithEmptyLogEntries() {
        List<LogEntry> logEntries = new ArrayList<>();
        List<Alert> alerts = detectionEngine.detect(logEntries);
        assertTrue(alerts.isEmpty());
    }

    // Unit test – Negative and functional coverage: verifies that log entries which do not meet either rule's configured threshold produce no alerts.
    @Test
    public void testDetectWithNoMatchingRules() {
        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_SUCCESS, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 2), eventDetails));

        List<Alert> alerts = detectionEngine.detect(logEntries);

        assertTrue(alerts.isEmpty());
    }

    // Unit test – Functional and rule coverage: verifies that five consecutive failed SSH logins trigger one repeated-failure alert with the expected attempt count.
    @Test
    public void testDetectWithRepeatedFailureRule() {
        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 2), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 3), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 4), eventDetails));

        List<Alert> alerts = detectionEngine.detect(logEntries);

        assertEquals(1, alerts.size());
        assertEquals(5, alerts.get(0).getFailedAttemptCount());
        assertTrue(DetectionRuleType.REPEATED_FAILED_SSH_LOGINS == alerts.get(0).getRuleType());
    }

    // Unit test – Functional and rule coverage: verifies that a successful login following five failed attempts triggers both applicable detection alerts.
    @Test
    public void testDetectWithSuccessAfterRepeatedFailureRule() {
        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 2), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 3), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 4), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_SUCCESS, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 5), eventDetails));

        List<Alert> alerts = detectionEngine.detect(logEntries);

        // There are 2 alerts because both rules will be triggered when there is a success after repeated failures.
        assertEquals(2, alerts.size());
        assertEquals(5, alerts.get(1).getFailedAttemptCount());
        assertTrue(DetectionRuleType.SUCCESSFUL_LOGIN_AFTER_FAILURES == alerts.get(1).getRuleType());

    }

    // Unit test – Combined rule coverage: verifies that both detection rules generate alerts when five failed attempts are followed by a successful login.
    @Test
    public void testDetectWithBothRules() {
        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 2), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 3), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 4), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_SUCCESS, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 5), eventDetails));

        List<Alert> alerts = detectionEngine.detect(logEntries);

        assertEquals(2, alerts.size());
        assertTrue(DetectionRuleType.REPEATED_FAILED_SSH_LOGINS == alerts.get(0).getRuleType() && DetectionRuleType.SUCCESSFUL_LOGIN_AFTER_FAILURES == alerts.get(1).getRuleType());
        assertTrue(alerts.get(0).getFailedAttemptCount() == 5 && alerts.get(1).getFailedAttemptCount() == 5);
    }

    // Unit test – Custom configuration and boundary coverage: verifies that both detection rules trigger at the configured threshold of three failed attempts.
    @Test
    public void testDetectWithCustomConfig() {
        DetectionConfig customConfig = new DetectionConfig(3, 3);
        detectionEngine = new DetectionEngine(customConfig);

        List<LogEntry> logEntries = new ArrayList<>();

        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 0), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 1), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_FAILURE, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 2), eventDetails));
        logEntries.add(new LogEntry(EventType.SSH_LOGIN_SUCCESS, "192.168.0.50", "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 3), eventDetails));

        List<Alert> alerts = detectionEngine.detect(logEntries);

        assertEquals(2, alerts.size());
        assertTrue(DetectionRuleType.REPEATED_FAILED_SSH_LOGINS == alerts.get(0).getRuleType() && DetectionRuleType.SUCCESSFUL_LOGIN_AFTER_FAILURES == alerts.get(1).getRuleType());
        assertTrue(alerts.get(0).getFailedAttemptCount() == 3 && alerts.get(1).getFailedAttemptCount() == 3);
    }
}
