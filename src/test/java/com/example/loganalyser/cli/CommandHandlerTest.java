package com.example.loganalyser.cli;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;

import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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

    @Test 
    public void testHelpCommand() {
        String input = "loganalyser --help\nloganalyser --exit\n";
        System.setIn(new ByteArrayInputStream(input.getBytes()));

        commandHandler.runCli();

        String output = outputStream.toString();
        assertTrue(output.contains("Available commands:"));
    }

    @Test 
    public void testExitCommand() {
        String input = "loganalyser --exit\n";
        System.setIn(new ByteArrayInputStream(input.getBytes()));

        commandHandler.runCli();

        String output = outputStream.toString();
        assertTrue(output.contains("Exiting..."));
    }

    @Test 
    public void testVersionCommand() {
        String input = "loganalyser --version\nloganalyser --exit\n";
        System.setIn(new ByteArrayInputStream(input.getBytes()));

        commandHandler.runCli();

        String output = outputStream.toString();
        assertTrue(output.contains("Log Analyser Version:"));
    }

    @Test 
    public void testInvalidCommand() {
        String input = "invalidcommand\nloganalyser --exit\n";
        System.setIn(new ByteArrayInputStream(input.getBytes()));

        commandHandler.runCli();

        String output = outputStream.toString();
        assertTrue(output.contains("Invalid command. Use the command loganalyser --help to see all commands available."));
    }

    @Test
    public void testAnalyseCommand() {
        String input = "loganalyser --analyse\nsrc/test/java/com/example/loganalyser/resources/logs/sample.log\nloganalyser --exit\n";
        System.setIn(new ByteArrayInputStream(input.getBytes()));

        commandHandler.runCli();

        String output = outputStream.toString();
        assertTrue(output.contains("Please enter the path to the log file you want to analyse:"));
    }

    @Test 
    public void testValidCapitalLettersCommand() {
        String input = "loganalyser --VERSION \nLOGANALYSER --EXIT\n";
        System.setIn(new ByteArrayInputStream(input.getBytes()));

        commandHandler.runCli();

        String output = outputStream.toString();
        assertTrue(output.contains("Log Analyser Version:"));
    }

    @Test 
    public void testInvalidCapitalLettersCommand() {
        String input = "loganalyser --INVALID \nLOGANALYSER --EXIT\n";

        System.setIn(new ByteArrayInputStream(input.getBytes()));

        commandHandler.runCli();

        String output = outputStream.toString();
        assertTrue(output.contains("Invalid command. Use the command loganalyser --help to see all commands available."));

    }

}