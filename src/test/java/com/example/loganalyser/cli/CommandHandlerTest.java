package com.example.loganalyser.cli;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;

import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

// Unit tests for CommandHandler, covering CLI command execution, valid and invalid commands, case handling and application exit behaviour.
// Tests the interaction between the command handler and its CLI input/output using simulated user input.
public class CommandHandlerTest {

    private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    private CommandHandler commandHandler;
    private final PrintStream originalOut = System.out;
    private final InputStream originalIn = System.in;

    @BeforeEach
    public void setUp() {
        System.setOut(new PrintStream(outputStream));
        commandHandler = new CommandHandler();

    }

    @AfterEach
    public void tearDown() {
        System.setOut(originalOut);
        System.setIn(originalIn);
    }

    // Unit test – Functional and output coverage: verifies that the help command displays the available CLI commands.
    @Test
    public void testHelpCommand() {
        String input = "loganalyser --help\nloganalyser --exit\n";
        System.setIn(new ByteArrayInputStream(input.getBytes()));

        commandHandler.runCli();

        String output = outputStream.toString();
        assertTrue(output.contains("Available commands:"));
    }

    // Unit test – Functional and output coverage: verifies that the exit command displays the exit message.
    @Test
    public void testExitCommand() {
        String input = "loganalyser --exit\n";
        System.setIn(new ByteArrayInputStream(input.getBytes()));

        commandHandler.runCli();

        String output = outputStream.toString();
        assertTrue(output.contains("Exiting..."));
    }

    // Unit test – Functional and output coverage: verifies that the version command displays the application version.
    @Test
    public void testVersionCommand() {
        String input = "loganalyser --version\nloganalyser --exit\n";
        System.setIn(new ByteArrayInputStream(input.getBytes()));

        commandHandler.runCli();

        String output = outputStream.toString();
        assertTrue(output.contains("Log Analyser Version:"));
    }

    // Unit test – Negative input validation coverage: verifies that an unrecognised command displays an invalid command message.
    @Test
    public void testInvalidCommand() {
        String input = "invalidcommand\nloganalyser --exit\n";
        System.setIn(new ByteArrayInputStream(input.getBytes()));

        commandHandler.runCli();

        String output = outputStream.toString();
        assertTrue(output.contains("Invalid command. Use the command loganalyser --help to see all commands available."));
    }

    // Unit test – Functional and interaction coverage: verifies that the analyse command prompts the user for a log file path.
    @Test
    public void testAnalyseCommand() {
        String input = "loganalyser --analyse\nsrc/test/java/com/example/loganalyser/resources/logs/sample.log\nloganalyser --exit\n";
        System.setIn(new ByteArrayInputStream(input.getBytes()));

        commandHandler.runCli();

        String output = outputStream.toString();
        assertTrue(output.contains("Please enter the path to the log file you want to analyse:"));
    }

    // Unit test – Functional and integration coverage: verifies that analysing a log file containing alert-triggering entries allows alerts to be displayed.
    @Test
    public void testAlertsCommandWhenAlertsExist() {
        String input = "loganalyser --analyse\nsrc/test/java/com/example/loganalyser/resources/logs/command_alerts_test.log\nloganalyser --alerts\nloganalyser --exit\n";
        System.setIn(new ByteArrayInputStream(input.getBytes()));

        commandHandler.runCli();

        String output = outputStream.toString();
        assertTrue(output.contains("                     SECURITY ALERT\n"));

    }

    // Unit test – Edge-case and output coverage: verifies that the alerts command displays a message when no alerts are available.
    @Test
    public void testAlertsCommandWhenNoAlertsExist() {
        String input = "loganalyser --alerts\nloganalyser --exit\n";
        System.setIn(new ByteArrayInputStream(input.getBytes()));

        commandHandler.runCli();

        String output = outputStream.toString();
        assertTrue(output.contains("No alerts available."));
    }

    // Unit test – Functional and interaction coverage: verifies that the report command prompts the user for a directory in which to save the report.
    @Test
    public void testReportCommand() {
        String input = "loganalyser --analyse\nsrc/test/java/com/example/loganalyser/resources/logs/command_alerts_test.log\nloganalyser --report\n\nloganalyser --exit\n";
        System.setIn(new ByteArrayInputStream(input.getBytes()));

        commandHandler.runCli();

        String output = outputStream.toString();
        assertTrue(output.contains("Please enter the directory to save the report:"));
    }

    // Unit test – Functional and output coverage: verifies that the config command opens and displays the configuration menu.
    @Test
    public void testConfigCommand() {
        String input = "loganalyser --config\n\nloganalyser --exit\n";
        System.setIn(new ByteArrayInputStream(input.getBytes()));

        commandHandler.runCli();

        String output = outputStream.toString();
        assertTrue(output.contains("                       CONFIG MENU"));
    }

    // Unit test – Functional and output coverage: verifies that the summary command displays the analysis summary heading.
    @Test
    public void testSummaryCommand() {
        String input = "loganalyser --summary\nloganalyser --exit\n";
        System.setIn(new ByteArrayInputStream(input.getBytes()));

        commandHandler.runCli();

        String output = outputStream.toString();
        assertTrue(output.contains("                    ANALYSIS SUMMARY"));
    }

    // Unit test – Input handling and case-insensitivity coverage: verifies that the version and exit commands are accepted when entered in uppercase.
    @Test
    public void testValidCapitalLettersCommand() {
        String input = "loganalyser --VERSION \nLOGANALYSER --EXIT\n";
        System.setIn(new ByteArrayInputStream(input.getBytes()));

        commandHandler.runCli();

        String output = outputStream.toString();
        assertTrue(output.contains("Log Analyser Version:"));
    }

    // Unit test – Negative input validation and case-handling coverage: verifies that an invalid uppercase command is rejected.
    @Test
    public void testInvalidCapitalLettersCommand() {
        String input = "loganalyser --INVALID \nLOGANALYSER --EXIT\n";

        System.setIn(new ByteArrayInputStream(input.getBytes()));

        commandHandler.runCli();

        String output = outputStream.toString();
        assertTrue(output.contains("Invalid command. Use the command loganalyser --help to see all commands available."));

    }

}
