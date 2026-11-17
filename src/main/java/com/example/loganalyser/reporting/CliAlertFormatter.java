package com.example.loganalyser.reporting;
import com.example.loganalyser.model.Alert;

public class CliAlertFormatter {

    // ANSI escape codes for colours stored . It is justified to store as a constant over a variable because these values are fixed and do not change during the execution of the program. Using constants improves code readability and maintainability, as it clearly indicates that these values are intended to be constant and should not be modified.
    private static final String RED = "\u001B[31m";


    // ANSI escape code to reset the color back to default. It is justified to store as a constant over a variable because these values are fixed and do not change during the execution of the program. Using constants improves code readability and maintainability, as it clearly indicates that these values are intended to be constant and should not be modified. It is also needed to ensure that the user interface returns to the default colour displaying coloured text, preventing the entire console output from being affected by the colour formatting.
    private static final String RESET = "\u001B[0m";


    // Method to format an alert into an aesthetically pleasing way for the user. This is for a nice readable output that is clear. The method returns a string so that the alerts generated can be 
    public String formatAlert(Alert alert) {

      // Use the stringbuilder to create a string for the security alert
      StringBuilder formattedAlert = new StringBuilder();

        // Make the banners colour red
        formattedAlert.append(RED + "============================================================\n");
        formattedAlert.append("                     SECURITY ALERT\n");
        formattedAlert.append("============================================================\n" + RESET);

        // Reset the colour back to its original
        

         // Segment the rule details for easier visualisation
        formattedAlert.append("------------------------------------------------------------\n");
        formattedAlert.append("RULE INFORMATION\n");
        formattedAlert.append("------------------------------------------------------------\n");

        // Print out the rule that triggered the alert
        formattedAlert.append("Rule        : ").append(alert.getRuleName()).append("\n");

        // Print out the Description of the rule
        formattedAlert.append("Description: ").append(alert.getRuleDescription()).append("\n\n");

        // Segment the source details for easier visualisation
        formattedAlert.append("------------------------------------------------------------\n");
        formattedAlert.append("SOURCE DETAILS\n");
        formattedAlert.append("------------------------------------------------------------\n");

        // Print out the associated username and IP
        formattedAlert.append("Source IP   : ").append(alert.getSourceIp()).append("\n");
        formattedAlert.append("Username    : ").append(alert.getUsername()).append("\n\n");

        // Segment the event details for easier visualisation
        formattedAlert.append("------------------------------------------------------------\n");
        formattedAlert.append("EVENT DETAILS\n");
        formattedAlert.append("------------------------------------------------------------\n");

        // Print out the event details
        formattedAlert.append("Failed Attempts : ").append(alert.getFailedAttemptCount()).append("\n");
        formattedAlert.append("Date            : ").append(alert.getDate()).append("\n");
        formattedAlert.append("Time            : ").append(alert.getTime()).append("\n");
        formattedAlert.append(alert.getEventDetails()).append("\n\n");

        formattedAlert.append("============================================================\n\n");

        return formattedAlert.toString();
    }
}

