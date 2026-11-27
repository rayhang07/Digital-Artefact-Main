package com.example.loganalyser.cli;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalTime;
import java.time.MonthDay;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.example.loganalyser.model.Alert;
import com.example.loganalyser.model.DetectionRuleType;

// Unit tests for CommandReport, covering report generation, path input handling, invalid paths and report generation failure conditions.
// Tests the behaviour of report generation using controlled alert data, temporary directories and simulated user input.
public class CommandReportTest {

    private CommandAlerts commandAlerts;
    private CommandReport commandReport;
    private PrintStream originalOut;
    private ByteArrayOutputStream outputStream;
    private Alert alert;

    @BeforeEach
    public void setUp() {

        commandAlerts = new CommandAlerts();
        commandReport = new CommandReport(commandAlerts);
        outputStream = new ByteArrayOutputStream();
        originalOut = System.out;
        System.setOut(new PrintStream(outputStream));
        String eventDetails = "Authentication method: password\n" + "Source port: 22\n" + "SSH protocol: 2";
        alert = new Alert(DetectionRuleType.REPEATED_FAILED_SSH_LOGINS, "Repeated Failed SSH Logins", "192.168.0.50", "Detects repeated failed SSH attempts from one IP", 5, "labadmin", MonthDay.of(11, 20), LocalTime.of(9, 4), eventDetails);

    }

    @AfterEach
    public void tearDown() {
        System.setOut(originalOut);

    }

    @TempDir
    Path testDirectoryPath;

    // Unit test – Functional and output coverage: verifies that a report is successfully generated when a valid directory path and alert are provided.
    @Test
    public void testHandleReportWithValidPath() throws Exception {
        List<Alert> alerts = new ArrayList<>();
        alerts.add(alert);
        commandAlerts.addAlerts(alerts);
        Scanner scanner = new Scanner(testDirectoryPath.toString());
        commandReport.handleReport(scanner);
        String actualOutput = outputStream.toString();
        assertTrue(actualOutput.contains("Successfully generated report at " + testDirectoryPath));
    }

    // Unit test – Input handling and functional coverage: verifies that a directory path enclosed in quotation marks is accepted for report generation.
    @Test
    public void testHandleReportWithQuotes() throws Exception {
        List<Alert> alerts = new ArrayList<>();
        alerts.add(alert);
        commandAlerts.addAlerts(alerts);
        Scanner scanner = new Scanner("\"" + testDirectoryPath + "\"");
        commandReport.handleReport(scanner);
        String actualOutput = outputStream.toString();
        assertTrue(actualOutput.contains("Successfully generated report at " + testDirectoryPath));
    }

    // Unit test – Input handling and functional coverage: verifies that a valid directory path containing spaces is accepted for report generation.
    @Test
    public void testHandleReportWithPathContainingSpaces() throws Exception {
        List<Alert> alerts = new ArrayList<>();
        alerts.add(alert);
        commandAlerts.addAlerts(alerts);
        Path directoryWithSpaces = Files.createDirectory(testDirectoryPath.resolve("Security Reports"));
        Scanner scanner = new Scanner(directoryWithSpaces.toString());
        commandReport.handleReport(scanner);
        String actualOutput = outputStream.toString();
        assertTrue(actualOutput.contains("Successfully generated report at " + directoryWithSpaces));
    }

    // Unit test – Negative input validation coverage: verifies that a path with mismatched quotation marks is rejected with an appropriate error message.
    @Test
    public void testHandleReportWithMismatchedQuotes() {
        Scanner scanner = new Scanner("\"" + testDirectoryPath);
        commandReport.handleReport(scanner);
        String actualOutput = outputStream.toString();
        assertTrue(actualOutput.contains("Error: Mismatched quotes in the report file path."));
    }

    // Unit test – Edge-case and input validation coverage: verifies that an empty path is rejected with an appropriate error message.
    @Test
    public void testHandleReportWithEmptyPath() {
        Scanner scanner = new Scanner("\n");
        commandReport.handleReport(scanner);
        String actualOutput = outputStream.toString();
        assertTrue(actualOutput.contains("Error: No report file path provided."));
    }

    // Unit test – Negative input validation coverage: verifies that report generation fails when the specified directory does not exist.
    @Test
    public void testHandleReportWithNonexistentDirectory() {
        Path invalidPath = testDirectoryPath.resolve("nonexistent");
        Scanner scanner = new Scanner(invalidPath.toString());
        commandReport.handleReport(scanner);
        String actualOutput = outputStream.toString();
        assertTrue(actualOutput.contains("Unable to generate pdf at "));
    }

    // Unit test – Edge-case and negative condition coverage: verifies that report generation is prevented when no alerts are available.
    @Test
    public void testHandleReportWithNoAlerts() {
        Scanner scanner = new Scanner(testDirectoryPath.toString());
        commandReport.handleReport(scanner);
        String actualOutput = outputStream.toString();
        assertTrue(actualOutput.contains("Unable to generate pdf at "));
        assertTrue(actualOutput.contains("Cannot generate a report because no alerts were detected"));
    }

}
