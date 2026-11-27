package com.example.loganalyser.cli;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.Scanner;

import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.example.loganalyser.config.DetectionConfig;

// Unit tests for CommandConfig, covering configuration display, threshold updates, input validation and rejection of invalid threshold values.
// Tests the behaviour of individual configuration operations using controlled CLI input.
public class CommandConfigTest {

    private CommandConfig commandConfig;
    private ByteArrayOutputStream outputStream;
    private PrintStream originalOut;

    @BeforeEach
    public void setUp() {
        commandConfig = new CommandConfig();
        outputStream = new ByteArrayOutputStream();
        originalOut = System.out;
        System.setOut(new PrintStream(outputStream));
    }

    @AfterEach
    public void tearDown() {
        System.setOut(originalOut);
    }

    // Unit test – Functional and output coverage: verifies that the current IP and time failure thresholds are displayed correctly.
    @Test
    public void testHandleConfigWithViewConfig() {
        DetectionConfig detectionConfig = commandConfig.getDetectionConfig();
        Scanner cliScanner = new Scanner("view config\n");
        commandConfig.handleConfig(cliScanner);
        String output = outputStream.toString();
        assertTrue(output.contains("IP failure threshold: " + detectionConfig.getIpFailureThreshold()));
        assertTrue(output.contains("Time Threshold " + detectionConfig.getTimeFailureThreshold()));
    }

    // Unit test – Negative input validation coverage: verifies that an unrecognised configuration command is rejected.
    @Test
    public void testHandleConfigWithInvalidCommand() {
        Scanner cliScanner = new Scanner("invalid command\n");
        commandConfig.handleConfig(cliScanner);
        assertTrue(outputStream.toString().contains("Invalid operation"));
    }

    // Unit test – Functional and state coverage: verifies that a valid IP failure threshold is updated without changing the time threshold.
    @Test
    public void testUpdateIpConfigWithValidInput() {
        int originalTimeThreshold = commandConfig.getDetectionConfig().getTimeFailureThreshold();
        Scanner cliScanner = new Scanner("7\n");
        commandConfig.updateIpConfig(cliScanner);
        int updatedIpThreshold = commandConfig.getDetectionConfig().getIpFailureThreshold();
        int updatedTimeThreshold = commandConfig.getDetectionConfig().getTimeFailureThreshold();
        assertEquals(7, updatedIpThreshold);
        assertEquals(originalTimeThreshold, updatedTimeThreshold);
        assertTrue(outputStream.toString().contains("Config updated sucessfully"));
    }

    // Unit test – Functional and state coverage: verifies that a valid time failure threshold is updated without changing the IP threshold.
    @Test
    public void testUpdateTimeConfigWithValidInput() {
        int originalIpThreshold = commandConfig.getDetectionConfig().getIpFailureThreshold();
        Scanner cliScanner = new Scanner("8\n");
        commandConfig.updateTimeConfig(cliScanner);
        int updatedIpThreshold = commandConfig.getDetectionConfig().getIpFailureThreshold();
        int updatedTimeThreshold = commandConfig.getDetectionConfig().getTimeFailureThreshold();
        assertEquals(originalIpThreshold, updatedIpThreshold);
        assertEquals(8, updatedTimeThreshold);
        assertTrue(outputStream.toString().contains("Config updated sucessfully"));
    }

    // Unit test – Edge-case and input validation coverage: verifies that empty input is rejected and the existing IP threshold remains unchanged.
    @Test
    public void testUpdateIpConfigWithEmptyInput() {
        int originalIpThreshold = commandConfig.getDetectionConfig().getIpFailureThreshold();
        Scanner cliScanner = new Scanner("\n");
        commandConfig.updateIpConfig(cliScanner);
        int updatedIpThreshold = commandConfig.getDetectionConfig().getIpFailureThreshold();
        assertEquals(originalIpThreshold, updatedIpThreshold);
        assertTrue(outputStream.toString().contains("threshold cannot be empty"));
    }

    // Unit test – Edge-case and input validation coverage: verifies that empty input is rejected and the existing time threshold remains unchanged.
    @Test
    public void testUpdateTimeConfigWithEmptyInput() {
        int originalTimeThreshold = commandConfig.getDetectionConfig().getTimeFailureThreshold();
        Scanner cliScanner = new Scanner("\n");
        commandConfig.updateTimeConfig(cliScanner);
        int updatedTimeThreshold = commandConfig.getDetectionConfig().getTimeFailureThreshold();
        assertEquals(originalTimeThreshold, updatedTimeThreshold);
        assertTrue(outputStream.toString().contains("threshold cannot be empty"));
    }

    // Unit test – Negative input validation coverage: verifies that non-numeric input is rejected for the IP threshold without changing its value.
    @Test
    public void testUpdateIpConfigWithNonNumericInput() {
        int originalIpThreshold = commandConfig.getDetectionConfig().getIpFailureThreshold();
        Scanner cliScanner = new Scanner("abc\n");
        commandConfig.updateIpConfig(cliScanner);
        int updatedIpThreshold = commandConfig.getDetectionConfig().getIpFailureThreshold();
        assertEquals(originalIpThreshold, updatedIpThreshold);
        assertTrue(outputStream.toString().contains("IP threshold must be a valid integer"));
    }

    // Unit test – Negative input validation coverage: verifies that non-numeric input is rejected for the time threshold without changing its value.
    @Test
    public void testUpdateTimeConfigWithNonNumericInput() {
        int originalTimeThreshold = commandConfig.getDetectionConfig().getTimeFailureThreshold();
        Scanner cliScanner = new Scanner("abc\n");
        commandConfig.updateTimeConfig(cliScanner);
        int updatedTimeThreshold = commandConfig.getDetectionConfig().getTimeFailureThreshold();
        assertEquals(originalTimeThreshold, updatedTimeThreshold);
        assertTrue(outputStream.toString().contains("Time threshold must be a valid integer"));
    }

    // Unit test – Boundary and negative input coverage: verifies that a zero IP failure threshold is rejected and the existing value is preserved.
    @Test
    public void testUpdateIpConfigWithZeroInput() {
        int originalIpThreshold = commandConfig.getDetectionConfig().getIpFailureThreshold();
        Scanner cliScanner = new Scanner("0\n");
        commandConfig.updateIpConfig(cliScanner);
        int updatedIpThreshold = commandConfig.getDetectionConfig().getIpFailureThreshold();
        assertEquals(originalIpThreshold, updatedIpThreshold);
        assertTrue(outputStream.toString().contains("Unable to update config"));
    }

    // Unit test – Boundary and negative input coverage: verifies that a zero time failure threshold is rejected and the existing value is preserved.
    @Test
    public void testUpdateTimeConfigWithZeroInput() {
        int originalTimeThreshold = commandConfig.getDetectionConfig().getTimeFailureThreshold();
        Scanner cliScanner = new Scanner("0\n");
        commandConfig.updateTimeConfig(cliScanner);
        int updatedTimeThreshold = commandConfig.getDetectionConfig().getTimeFailureThreshold();
        assertEquals(originalTimeThreshold, updatedTimeThreshold);
        assertTrue(outputStream.toString().contains("Unable to update config"));
    }

    // Unit test – Boundary and negative input coverage: verifies that a negative IP failure threshold is rejected and the existing value is preserved.
    @Test
    public void testUpdateIpConfigWithNegativeInput() {
        int originalIpThreshold = commandConfig.getDetectionConfig().getIpFailureThreshold();
        Scanner cliScanner = new Scanner("-1\n");
        commandConfig.updateIpConfig(cliScanner);
        int updatedIpThreshold = commandConfig.getDetectionConfig().getIpFailureThreshold();
        assertEquals(originalIpThreshold, updatedIpThreshold);
        assertTrue(outputStream.toString().contains("Unable to update config"));
    }

    // Unit test – Boundary and negative input coverage: verifies that a negative time failure threshold is rejected and the existing value is preserved.
    @Test
    public void testUpdateTimeConfigWithNegativeInput() {
        int originalTimeThreshold = commandConfig.getDetectionConfig().getTimeFailureThreshold();
        Scanner cliScanner = new Scanner("-1\n");
        commandConfig.updateTimeConfig(cliScanner);
        int updatedTimeThreshold = commandConfig.getDetectionConfig().getTimeFailureThreshold();
        assertEquals(originalTimeThreshold, updatedTimeThreshold);
        assertTrue(outputStream.toString().contains("Unable to update config"));
    }
}
