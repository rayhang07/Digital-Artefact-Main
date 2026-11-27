package com.example.loganalyser.cli;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Scanner;

import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

// Unit tests for CommandAnalysis, covering log file path validation, input handling, file accessibility and analysis output.
// Tests the behaviour of the analysis command when supplied with valid and invalid file paths.
public class CommandAnalysisTest {

    private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    private CommandAnalysis commandAnalysis;
    private Scanner scanner;
    private CommandAlerts commandAlerts;
    private final PrintStream originalOut = System.out;
    private CommandConfig commandConfig;
    private CommandSummary commandSummary;


    // Provide setup shared setup for each test
    @BeforeEach
    public void setUp() {
        System.setOut(new PrintStream(outputStream));
        commandConfig = new CommandConfig();
        commandAlerts = new CommandAlerts();
        commandSummary = new CommandSummary(commandAlerts);
        commandAnalysis = new CommandAnalysis(commandConfig, commandSummary);

    }

    // Restore test environment after each test restoring original output 
    @AfterEach
    public void tearDown() {
        System.setOut(originalOut);
    }

    // Unit test – Negative input validation coverage: verifies that a file path containing mismatched quotation marks is rejected with an appropriate error message.
    @Test
    public void testHandleAnalysisWithMismatchedQuotes() {
        Scanner scanner = new Scanner("\"invalid/path/to/logfile.log\n");
        commandAnalysis.handleAnalysis(scanner, commandAlerts);

        String output = outputStream.toString();
        assertTrue(output.contains("Error: Mismatched quotes in the log file path."));
    }

    // Unit test – Functional and output coverage: verifies that a valid unquoted log file path is accepted and analysis category counts are displayed.
    @Test
    public void testHandleAnalysisWithValidPath() {
        // Assuming you have a valid log file at this path for testing
        Scanner scanner = new Scanner("src/test/java/com/example/loganalyser/resources/logs/sample.log\n");
        commandAnalysis.handleAnalysis(scanner, commandAlerts);

        String output = outputStream.toString();
        assertTrue(output.contains("Analysing log file at: "));
        assertTrue(output.contains("Recognised entries:"));
        assertTrue(output.contains("Malformed entries:"));
        assertTrue(output.contains("Unrecognised entries:"));
    }

    // Unit test – Input handling and functional coverage: verifies that a valid file path enclosed in quotation marks is accepted and analysed.
    @Test
    public void testHandleAnalysisWithQuotes() {
        Scanner scanner = new Scanner("\"src/test/java/com/example/loganalyser/resources//logs/sample.log\"\n");
        commandAnalysis.handleAnalysis(scanner, commandAlerts);

        String output = outputStream.toString();
        assertTrue(output.contains("Analysing log file at: "));
        assertTrue(output.contains("Recognised entries:"));
        assertTrue(output.contains("Malformed entries:"));
        assertTrue(output.contains("Unrecognised entries:"));
    }

    // Unit test – Negative input validation coverage: verifies that a directory path is rejected because it is not a regular file.
    @Test
    public void testHandleAnalysisWithNonRegularFile() {
        Scanner scanner = new Scanner("src/test/java/com/example/loganalyser/resources/logs/\n");
        commandAnalysis.handleAnalysis(scanner, commandAlerts);

        String output = outputStream.toString();
        assertTrue(output.contains("Error: The specified path is not a regular file."));
    }

    // Unit test – Negative input validation coverage: verifies that a path to a non-existent log file is rejected with an appropriate error message.
    @Test
    public void testHandleAnalysisWithNonExistentFile() {
        Scanner scanner = new Scanner("src/test/java/com/example/loganalyser/resources/logs/nonexistent.log\n");
        commandAnalysis.handleAnalysis(scanner, commandAlerts);

        String output = outputStream.toString();
        assertTrue(output.contains("Error: The specified log file does not exist."));
    }

    // Unit test – File accessibility and error-handling coverage: verifies that an unreadable log file is rejected on Linux with an appropriate error message.
    @Test
    @EnabledOnOs(OS.LINUX)
    public void testHandleAnalysisWithUnreadableFile() throws IOException {
        Path path = java.nio.file.Paths.get("src/test/java/com/example/loganalyser/resources/logs/unreadable.log");
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("---------"));
        Scanner scanner = new Scanner(path.toString() + "\n");
        commandAnalysis.handleAnalysis(scanner, commandAlerts);

        String output = outputStream.toString();
        System.out.println(outputStream.toString());
        assertTrue(output.contains("Error: The specified log file is not readable."));

        Files.setPosixFilePermissions(
                path,
                PosixFilePermissions.fromString("rw-r--r--")
        );
    }
}
