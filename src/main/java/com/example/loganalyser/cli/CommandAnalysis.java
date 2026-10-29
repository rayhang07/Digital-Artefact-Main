package com.example.loganalyser.cli;
import java.util.Scanner;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;

public class CommandAnalysis {
    
    public void handleAnalysis(Scanner cliScanner) {
        System.out.println("Please enter the path to the log file you want to analyse:");
        String logFilePath = cliScanner.nextLine();
        if (logFilePath.startsWith("\"") && logFilePath.endsWith("\"")) {
            logFilePath = logFilePath.substring(1, logFilePath.length() - 1);
        }
        if (!verifyLogFilePath(logFilePath)) {
            return;
        }
    }

    private boolean verifyLogFilePath(String logFilePath) {
        Path path = Paths.get(logFilePath);
        if(logFilePath.isEmpty()) {
            System.out.println("Error: No log file path provided.");
            return false;
        }
        else if (!Files.exists(path)) {
            System.out.println("Error: The specified log file does not exist.");
            return false;
        }
        else if (!Files.isRegularFile(path)) {
            System.out.println("Error: The specified path is not a regular file.");
            return false;
        }
        else if (!Files.isReadable(path)) {
            System.out.println("Error: The specified log file is not readable.");
            return false;
        }
        System.out.println("Analysing log file at: " + logFilePath);
        return true; 
    }
}
