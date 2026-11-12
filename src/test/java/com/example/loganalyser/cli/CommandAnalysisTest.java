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

public class CommandAnalysisTest {
    private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    private CommandAnalysis commandAnalysis;
    private Scanner scanner;
    private CommandAlerts commandAlerts;
    private final PrintStream originalOut = System.out;
    

    @BeforeEach 
    public void setUp() {
        System.setOut(new PrintStream(outputStream));
        commandAnalysis = new CommandAnalysis();
        commandAlerts = new CommandAlerts();

    }

    @AfterEach
    public void tearDown() {
        System.setOut(originalOut);
        
    } 

    @Test
    public void testHandleAnalysisWithMismatchedQuotes() {
        Scanner scanner = new Scanner("\"invalid/path/to/logfile.log\n");
        commandAnalysis.handleAnalysis(scanner, commandAlerts);
    
        String output = outputStream.toString();
        assertTrue(output.contains("Error: Mismatched quotes in the log file path."));
    }

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
     
    @Test 
    public void testHandleAnalysisWithNonRegularFile() {
        Scanner scanner = new Scanner("src/test/java/com/example/loganalyser/resources/logs/\n");
        commandAnalysis.handleAnalysis(scanner, commandAlerts);

        String output = outputStream.toString();
        assertTrue(output.contains("Error: The specified path is not a regular file."));
    }

    @Test 
    public void testHandleAnalysisWithNonExistentFile() {
        Scanner scanner = new Scanner("src/test/java/com/example/loganalyser/resources/logs/nonexistent.log\n");
        commandAnalysis.handleAnalysis(scanner, commandAlerts);

        String output = outputStream.toString();
        assertTrue(output.contains("Error: The specified log file does not exist."));
    }

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
