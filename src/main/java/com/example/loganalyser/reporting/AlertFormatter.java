package com.example.loganalyser.reporting;
import com.example.loganalyser.model.Alert;

public class AlertFormatter {

    // ANSI escape codes for colours stored . It is justified to store as a constant over a variable because these values are fixed and do not change during the execution of the program. Using constants improves code readability and maintainability, as it clearly indicates that these values are intended to be constant and should not be modified.
    private static final String RED = "\u001B[31m";


    // ANSI escape code to reset the color back to default. It is justified to store as a constant over a variable because these values are fixed and do not change during the execution of the program. Using constants improves code readability and maintainability, as it clearly indicates that these values are intended to be constant and should not be modified. It is also needed to ensure that the user interface returns to the default colour displaying coloured text, preventing the entire console output from being affected by the colour formatting.
    private static final String RESET = "\u001B[0m";


    // Method to format an alert into an aesthetically pleasing way for the user. This is for a nice readable output that is clear
    public void formatAlert(Alert alert) {

        // Make the banners colour red
        System.out.println(RED);
        System.out.println("============================================================");
        System.out.println("                     SECURITY ALERT");
        System.out.println("============================================================");

        // Reset the colour back to its original
        System.out.println(RESET);

        // Print out the rule and rule type that triggered the alert
        System.out.println("Rule        : " + alert.getRuleName());
        System.out.println("Type        : " + alert.getRuleType());
        System.out.println();

        // Print out the Description of the alert
        System.out.println("Description: " + alert.getRuleDescription());
        System.out.println();

        // Segment the source details for easier visualisation
        System.out.println("------------------------------------------------------------");
        System.out.println("SOURCE DETAILS");
        System.out.println("------------------------------------------------------------");


        // Print out the associated username and IP
        System.out.println("Source IP   : " + alert.getSourceIp());
        System.out.println("Username    : " + alert.getUsername());
        System.out.println();

        // Segment the event details for easier visualisation
        System.out.println("------------------------------------------------------------");
        System.out.println("EVENT DETAILS");
        System.out.println("------------------------------------------------------------");

        // Print out the event details
        System.out.println("Failed Attempts : " + alert.getFailedAttemptCount());
        System.out.println("Date            : " + alert.getDate());
        System.out.println("Time            : " + alert.getTime());
        System.out.println(alert.getEventDetails());

        System.out.println();
        System.out.println("============================================================");
        System.out.println();
    }
}

