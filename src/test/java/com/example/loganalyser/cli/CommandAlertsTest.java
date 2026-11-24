package com.example.loganalyser.cli;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.time.LocalTime;
import java.time.MonthDay;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.example.loganalyser.model.Alert;
import com.example.loganalyser.model.DetectionRuleType;

public class CommandAlertsTest {
    private CommandAlerts commandAlerts;
    private Alert alert;
    private Alert secondAlert;
    private Alert duplicateAlert;
    private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    private PrintStream originalOut;

    @BeforeEach 
    public void setUp() {
        System.setOut(new PrintStream(outputStream));
        commandAlerts = new CommandAlerts();
        String eventDetails = "Authentication method: password\n" +"Source port: 22\n" + "SSH protocol: 2";
        alert = new Alert(DetectionRuleType.REPEATED_FAILED_SSH_LOGINS, "Repeated Failed SSH Logins", "192.168.0.50", "Multiple failed SSH login attempts", 5, "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 4), eventDetails);
        secondAlert = new Alert(DetectionRuleType.SUCCESSFUL_LOGIN_AFTER_FAILURES,  "Successful Login After Failures", "192.168.0.60", "Detects a successful SSH login following repeated failed login attempts", 3, "root",  MonthDay.of(11, 20), LocalTime.of(9, 10), eventDetails);
        duplicateAlert = new Alert(DetectionRuleType.SUCCESSFUL_LOGIN_AFTER_FAILURES,  "Successful Login After Failures", "192.168.0.60", "Detects a successful SSH login following repeated failed login attempts", 3, "root",  MonthDay.of(11, 20), LocalTime.of(9, 10), eventDetails);
    }

    @AfterEach 
    public void tearDown() {
        System.setOut(originalOut);
    }

    @Test 
    public void addNewAlert() {
        List<Alert> newAlerts = new ArrayList<>();
        newAlerts.add(alert);
        commandAlerts.addAlerts(newAlerts);

        List<Alert> storedAlerts = commandAlerts.getAlerts();
        assertEquals(1, storedAlerts.size());
        assertTrue(storedAlerts.contains(alert));
    }

    @Test 
    public void addDuplicateAlert() {
        List<Alert> duplicateAlerts = new ArrayList<>();
        duplicateAlerts.add(secondAlert);
        duplicateAlerts.add(duplicateAlert);
        commandAlerts.addAlerts(duplicateAlerts);

        List<Alert> storedAlerts = commandAlerts.getAlerts();
        assertEquals(1, storedAlerts.size());
        assertTrue(storedAlerts.contains(secondAlert));
    }

    @Test 
    public void displayAlerts() {
        List<Alert> newAlerts = new ArrayList<>();
        newAlerts.add(alert);
        newAlerts.add(secondAlert);

        commandAlerts.displayAlerts(newAlerts);
        String expectedFirstAlert = """
        \u001B[31m============================================================
                             SECURITY ALERT
        ============================================================
        \u001B[0m------------------------------------------------------------
        RULE INFORMATION
        ------------------------------------------------------------
        Rule        : Repeated Failed SSH Logins
        Description: Multiple failed SSH login attempts

        ------------------------------------------------------------
        SOURCE DETAILS
        ------------------------------------------------------------
        Source IP   : 192.168.0.50
        Username    : labadmin

        ------------------------------------------------------------
        EVENT DETAILS
        ------------------------------------------------------------
        Failed Attempts : 5
        Date            : --11-20
        Time            : 09:04
        Authentication method: password
        Source port: 22
        SSH protocol: 2

        ============================================================

        """;

        String expectedSecondAlert = """
        \u001B[31m============================================================
                             SECURITY ALERT
        ============================================================
        \u001B[0m------------------------------------------------------------
        RULE INFORMATION
        ------------------------------------------------------------
        Rule        : Successful Login After Failures
        Description: Detects a successful SSH login following repeated failed login attempts

        ------------------------------------------------------------
        SOURCE DETAILS
        ------------------------------------------------------------
        Source IP   : 192.168.0.60
        Username    : root

        ------------------------------------------------------------
        EVENT DETAILS
        ------------------------------------------------------------
        Failed Attempts : 3
        Date            : --11-20
        Time            : 09:10
        Authentication method: password
        Source port: 22
        SSH protocol: 2

        ============================================================

        """;

        String output = expectedFirstAlert + expectedSecondAlert;
        
        assertTrue(output.contains(expectedFirstAlert));
        assertTrue(output.contains(expectedSecondAlert));

    }

    @Test 
    public void displayEmptyAlerts() {
        List<Alert> newAlerts = new ArrayList<>();
        commandAlerts.displayAlerts(newAlerts);
        String output = outputStream.toString();
        assertTrue(output.contains("No alerts detected."));

    }

    @Test 
    public void handleAlerts() {
        List<Alert> newAlerts = new ArrayList<>();
        newAlerts.add(alert);
        newAlerts.add(secondAlert);

        commandAlerts.displayAlerts(newAlerts);
        String expectedFirstAlert = """
        \u001B[31m============================================================
                             SECURITY ALERT
        ============================================================
        \u001B[0m------------------------------------------------------------
        RULE INFORMATION
        ------------------------------------------------------------
        Rule        : Repeated Failed SSH Logins
        Description: Multiple failed SSH login attempts

        ------------------------------------------------------------
        SOURCE DETAILS
        ------------------------------------------------------------
        Source IP   : 192.168.0.50
        Username    : labadmin

        ------------------------------------------------------------
        EVENT DETAILS
        ------------------------------------------------------------
        Failed Attempts : 5
        Date            : --11-20
        Time            : 09:04
        Authentication method: password
        Source port: 22
        SSH protocol: 2

        ============================================================

        """;

        String expectedSecondAlert = """
        \u001B[31m============================================================
                             SECURITY ALERT
        ============================================================
        \u001B[0m------------------------------------------------------------
        RULE INFORMATION
        ------------------------------------------------------------
        Rule        : Successful Login After Failures
        Description: Detects a successful SSH login following repeated failed login attempts

        ------------------------------------------------------------
        SOURCE DETAILS
        ------------------------------------------------------------
        Source IP   : 192.168.0.60
        Username    : root

        ------------------------------------------------------------
        EVENT DETAILS
        ------------------------------------------------------------
        Failed Attempts : 3
        Date            : --11-20
        Time            : 09:10
        Authentication method: password
        Source port: 22
        SSH protocol: 2

        ============================================================

        """; 

        String output = expectedFirstAlert + expectedSecondAlert;
        
        assertTrue(output.contains(expectedFirstAlert));
        assertTrue(output.contains(expectedSecondAlert));

    }

    @Test 
    public void handleEmptyAlerts() {
        commandAlerts.handleAlerts();
        String output = outputStream.toString();
        assertTrue(output.contains("No alerts available."));

    }

}
