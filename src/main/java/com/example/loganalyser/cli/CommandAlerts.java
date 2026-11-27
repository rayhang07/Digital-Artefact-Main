package com.example.loganalyser.cli;

// import necessary util and packages
import java.util.ArrayList;
import java.util.List;

import com.example.loganalyser.model.Alert;
import com.example.loganalyser.reporting.CliAlertFormatter;


// Class to store all alerts and display alerts that are linked to the current analysis. This has been segmented from detection for modularity and strong seperation of duties between components of the applicatoin
public class CommandAlerts {
    // List to store all alerts
    private final List<Alert> alerts = new ArrayList<>();

    // Method to add alerts to list
    public void addAlerts(List<Alert> newAlerts) {

        // Loop through all alerts
        for (Alert alert : newAlerts) {

            // If the alert is not already stored in the list add it, this is to prevent duplicate alerts
            if (!alerts.contains(alert)) {
                alerts.add(alert);  
            }
        }
    }

    // Method to display alerts (when analysing)
    public void displayAlerts(List<Alert> alerts) {

        // If alerts are empty, display a message indicating theyre empty
        if (alerts.isEmpty()) {
            System.out.println("No alerts detected.");
            return;
        }

        // If not empty instantiate the alertformatter class 
        CliAlertFormatter alertFormatter = new CliAlertFormatter();

        // Loop through all alerts and use the formatter to format them to display to the user
        for (Alert alert : alerts) {
            System.out.println(alertFormatter.formatAlert(alert));
        }
    }

    // Method to handle alerts (from the alerts command)
    public void handleAlerts() {

        // If alerts are empty, display a message indicating theyre empty
        if (alerts.isEmpty()) {
            System.out.println("No alerts available.");
            return;
        }
        // If not empty instantiate the alertformatter class 
        CliAlertFormatter alertFormatter = new CliAlertFormatter();

        // Loop through all alerts and use the formatter to format them to display to the user        
        for (Alert alert : alerts) {
            System.out.println(alertFormatter.formatAlert(alert));
        }
    }

    // Getter to return the list of alerts so that they can be used when analysing or displaying alerts.
    public List<Alert> getAlerts() {
        return alerts;
    }
}