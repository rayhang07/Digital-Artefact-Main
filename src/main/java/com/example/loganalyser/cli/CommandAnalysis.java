package com.example.loganalyser.cli;
// import necessary packages
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;

import com.example.loganalyser.model.ParseResult;
import com.example.loganalyser.parser.LogParser;
public class CommandAnalysis {
    
    // Method to handle the analysis command, this will be called from the runCli method in the CommandHandler class. This is justified as it allows for a modular and organized approach to handling user commands, making it easier to add or modify commands in the future. It also improves code readability and maintainability, as the command handling logic is separated from the main method.
    public void handleAnalysis(Scanner cliScanner) {
        System.out.println("Please enter the path to the log file you want to analyse:");
       
       // Read the user input from the command line, store it in the logFilePath variable, and pass it to the verifyLogFilePath method to check if the log file path is valid. 
        String logFilePath = cliScanner.nextLine().trim();
        
        // Verify the log file path by calling the verifyLogFilePath method, which checks if the log file path is valid and prints an error message if it is not. 
        if (!verifyLogFilePath(logFilePath)) {
            return;
        }

        // Create a Path object from the log file path, create a LogParser object, and call the parseLogFile method to parse the log file. If an exception is thrown during parsing, print an error message and return. Otherwise, print the number of recognised, malformed, and unrecognised log entries.
        Path logPath = Path.of(logFilePath.replace("\"", ""));
        LogParser logParser = new LogParser();
        ParseResult parseResult;
        try {
             parseResult = logParser.parseLogFile(logPath);

        } 
        catch (Exception e) {
            System.out.println("Error analysing log file " + e.getMessage());
            return;
        }

        
        System.out.println("Recognised entries: " + parseResult.getLogEntries().size());
        System.out.println( "Malformed entries: " + parseResult.getMalformedEntries().size());
        System.out.println("Unrecognised entries: " + parseResult.getUnrecognisedEntries().size());
        
    }

    // Method to verify the log file path, this will be called from the handleAnalysis method in the CommandAnalysis class. This is justified as it allows for separating analysis logic from validation logic.
    private boolean verifyLogFilePath(String logFilePath) {


        // Check if the log file path exclusively starts or ends with a quote, if so print an error message and return false. This allows for handling user input that may contain quotes, which can cause issues when trying to access the log file.
        if (logFilePath.startsWith("\"") ^ logFilePath.endsWith("\"")) {
            System.out.println("Error: Mismatched quotes in the log file path.");
            return false;
        }

        // Check if the log file path starts and ends with quotes, if so remove the quotes from the log file path. This allows for handling user input that may contain quotes, which can cause issues when trying to access the log file.
        else if (logFilePath.startsWith("\"") && logFilePath.endsWith("\"")) {
            logFilePath = logFilePath.substring(1, logFilePath.length() - 1);
        }

        // Create a Path object from the log file path
        Path path = Paths.get(logFilePath);

        // Check if the log file path is empty, if so print an error message and return false. This allows for handling user input that may be empty, which can cause issues when trying to access the log file.
        if(logFilePath.isEmpty()) {
            System.out.println("Error: No log file path provided.");
            return false;
        }

        // Check if the log file path exists, if not print an error message and return false. This allows for handling user input that may be invalid, which can cause issues when trying to access the log file.
        else if (!Files.exists(path)) {
            System.out.println("Error: The specified log file does not exist.");
            return false;
        }

        // Check if the log file path is a regular file, if not print an error message and return false. This allows for handling user input that may be invalid, which can cause issues when trying to access the log file.
        else if (!Files.isRegularFile(path)) {
            System.out.println("Error: The specified path is not a regular file.");
            return false;
        }

        // Check if the log file path is readable, if not print an error message and return false. This allows for handling user input that may be invalid, which can cause issues when trying to access the log file.
        else if (!Files.isReadable(path)) {
            System.out.println("Error: The specified log file is not readable.");
            return false;
        }

        // If all checks pass, print a message indicating that the log file path is valid and return true. This allows for user input validation and ensures that the log file can be accessed and analysed without issues.
        System.out.println("Analysing log file at: " + logFilePath);
        return true; 
    }
}
