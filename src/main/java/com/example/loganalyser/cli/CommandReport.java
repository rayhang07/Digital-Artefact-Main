package com.example.loganalyser.cli;

//import necessary packages
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Scanner;

import com.example.loganalyser.model.Alert;
import com.example.loganalyser.reporting.PdfAlertFormatter;

// Class to generate a pdf report that can be saved to the device

public class CommandReport {

    // Private 
    private final CommandAlerts commandAlerts;
    
    // Constructor to ensure that once instantiated the report object can access the existing Command Alerts class to be able to access the list of alerts that already exists instead of instantiating a new object that would have an empty list
    public CommandReport(CommandAlerts commandAlerts) {
        this.commandAlerts = commandAlerts;
    }

    // Method to handle the generation of the pdf report
    public void handleReport(Scanner cliScanner) {
    
        // Output the ask the user to enter the directory they want to save the report to
        System.out.println();
        System.out.println("Please enter the directory to save the report:");
       
       // Read the user input from the command line, store it in the reportFilePath variable, and pass it to the verifyReportFilePath method to check if the path is valid. 
        String reportFilePath = cliScanner.nextLine().trim();

        // If the path cannot be verified by the method return the related error 
        if (!verifyReportPath(reportFilePath)) {
            return;
        }
            // Create a path object from the user input and remove any quotes
            Path pathToDirectory = Path.of(reportFilePath.replace("\"", ""));

            // Create a list of alerts using the getter method
            List<Alert> alerts = commandAlerts.getAlerts();

            try {
                // Instantiate an object from the alertformatter class 
                PdfAlertFormatter pdfAlertFormatter = new PdfAlertFormatter();

                //call the format method through the object providing the list of alerts and the path to the directory
                pdfAlertFormatter.formatPdf(alerts, pathToDirectory);
                
                // Output that the generation was successful and the path to where it has been saved
                System.out.println("Successfully generated report at " +pathToDirectory.toString());
            } 
            
            // Catch any IOException and IllegalStateExceptions and output an error message containing the exception to provide the user with correct feedback
            catch (IOException | IllegalStateException e) {
                System.out.println("Unable to generate pdf - "+e.getMessage());
            }
            
            
        

    }

    private boolean verifyReportPath(String reportFilePath) {
        // Check if the report file path exclusively starts or ends with a quote, if so print an error message and return false. This allows for handling user input that may contain quotes, which can cause issues when trying to access the log file.
        if (reportFilePath.startsWith("\"") ^ reportFilePath.endsWith("\"")) {
            System.out.println("Error: Mismatched quotes in the log file path.");
            return false;
        }

        // Check if the report file path starts and ends with quotes, if so remove the quotes from the log file path. This allows for handling user input that may contain quotes, which can cause issues when trying to access the log file.
        else if (reportFilePath.startsWith("\"") && reportFilePath.endsWith("\"")) {
            reportFilePath = reportFilePath.substring(1, reportFilePath.length() - 1);
        }

        // Create a Path object from the log file path
        Path path = Paths.get(reportFilePath);

        // Check if the report file path is empty, if so print an error message and return false. This allows for handling user input that may be empty, which can cause issues when trying to access the log file.
        if(reportFilePath.isEmpty()) {
            System.out.println("Error: No log file path provided.");
            return false;
        }

        // Create a path object to the parent directory 
        Path parentDirectory = path.getParent();
        
        // Returns true if the parent directory exists. This is done so that the file can be stored in a location that actually exists on the users device
        return Files.isDirectory(parentDirectory);
    }
}
