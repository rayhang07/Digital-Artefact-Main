package com.example.loganalyser.cli;
// import necessary packages
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Scanner;

import com.example.loganalyser.config.DetectionConfig;
import com.example.loganalyser.detection.DetectionEngine;
import com.example.loganalyser.model.Alert;
import com.example.loganalyser.model.ParseResult;
import com.example.loganalyser.parser.LogParser;
public class CommandAnalysis {
    
    private static final String GREEN = "\u001B[32m";
    
    private static final String RED = "\u001B[31m";
    // ANSI escape code to reset the color back to default. It is justified to store as a constant over a variable because these values are fixed and do not change during the execution of the program. Using constants improves code readability and maintainability, as it clearly indicates that these values are intended to be constant and should not be modified. It is also needed to ensure that the user interface returns to the default colour displaying coloured text, preventing the entire console output from being affected by the colour formatting.
    private static final String RESET = "\u001B[0m";
    // Method to handle the analysis command, this will be called from the runCli method in the CommandHandler class. This is justified as it allows for a modular and organized approach to handling user commands, making it easier to add or modify commands in the future. It also improves code readability and maintainability, as the command handling logic is separated from the main method.
    
    // Method to handle the analysis command
    public void handleAnalysis(Scanner cliScanner, CommandAlerts commandAlerts) {
        System.out.println();
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

        // Instantiate the config and engine in order to determine if thresholds for alerts have been triggered
        DetectionConfig detectionConfig = new DetectionConfig();
        DetectionEngine detectionEngine = new DetectionEngine(detectionConfig);
        // Using the detect method, create a list of any alerts and then add it to the list of all alerts
        List<Alert> alerts = detectionEngine.detect(parseResult.getLogEntries());
        commandAlerts.addAlerts(alerts);
        // Run the complete method to display the outcomes and then display the relevant alerts for this specific analysis
        analysisComplete(parseResult.getLogEntries().size(), parseResult.getMalformedEntries().size(), parseResult.getUnrecognisedEntries().size(), parseResult.getOtherSSHEntries().size(), alerts);
        commandAlerts.displayAlerts(alerts);

       
        
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

    // Method to display that analysis has been completed correctly taking as parameters important information
    private void analysisComplete(int logEntries, int malformedEntries, int unrecognisedEntries, int otherSshEntries, List<Alert> alerts) {
        // Display a banner to show analysis was complete
        System.out.println(GREEN);
        System.out.println("============================================================");
        System.out.println("                  SECURITY ANALYSIS COMPLETE");
        System.out.println("============================================================");
        System.out.println(RESET);

        System.out.println("Log file analysed successfully.");
        System.out.println();

        // Display the outcomes of analysis including the recognised, malformed, non authentication entries and unrecognised entries
        System.out.println("Recognised entries: " + logEntries);
        System.out.println("Malformed entries: " + malformedEntries);
        System.out.println("Other SSH entries: " + unrecognisedEntries);
        System.out.println("Unrecognised entries: " + otherSshEntries);
        System.out.println();

        // If alerts are empty display that there are no security alerts detected
        if (alerts.isEmpty()) {
            System.out.println(GREEN + "[+] NO SECURITY ALERTS DETECTED" + RESET);
        } 

        // If alerts are present display how many there are
        else {
            System.out.println(RED + "[!] " + alerts.size() + " SECURITY ALERT(S) DETECTED" + RESET);
        }
    }
}
