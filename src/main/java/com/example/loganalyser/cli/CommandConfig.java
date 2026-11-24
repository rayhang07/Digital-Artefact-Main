package com.example.loganalyser.cli;
import java.util.Scanner;

import com.example.loganalyser.config.DetectionConfig;


public class CommandConfig {
    private DetectionConfig detectionConfig = new DetectionConfig();

    public void handleConfig(Scanner cliScanner) {
        System.out.println("\n                Config menu\n"+ "---------------------------------------------------\nView config: see current failure thresholds\n"+ "Set IP failure threshold: set a new IP failure\n" +"Set time failure threshold: set a new time failure threshold\n");
        String choice = cliScanner.nextLine().toLowerCase().trim();
        switch (choice) {
            case "view config":
                System.out.println("\nIP failure threshold: "+detectionConfig.getIpFailureThreshold());
                System.out.println("Time Threshold "+ detectionConfig.getTimeFailureThreshold());
                break;
            case "set ip failure threshold":
                updateIpConfig(cliScanner);
                break;

            case "set time failure threshold":
                updateTimeConfig(cliScanner);
                break;
            default:
                System.out.println("Invalid command");
        }       
    }

    public void updateIpConfig(Scanner cliScanner) {
        System.out.println("\nEnter new IP failure threshold");
        String ipThreshold = cliScanner.nextLine().trim();
        int newIpThreshold = 0;


        if (ipThreshold.isEmpty()) {
            System.out.println("Threshold cannot be empty.");
            return;
        }

        try {
            newIpThreshold = Integer.parseInt(ipThreshold);
            // Continue with your configuration update
        }
        catch (NumberFormatException e) {
            System.out.println("Please enter a valid integer.");
        }  

        try {
            detectionConfig = new DetectionConfig(newIpThreshold, detectionConfig.getTimeFailureThreshold());
            System.out.println("\nConfig updated sucessfully");
        }
        
        catch (IllegalArgumentException e) {
            System.out.println("\nUnable to update config: " +e.getMessage());
        }
        
    }

    public void updateTimeConfig(Scanner cliScanner) {
        System.out.println("\nEnter new time failure threshold");
        String timeThreshold = cliScanner.nextLine().trim();
        int newTimeThreshold = 0;


        if (timeThreshold.isEmpty()) {
            System.out.println("Threshold cannot be empty.");
            return;
        }

        try {
            newTimeThreshold = Integer.parseInt(timeThreshold);
            // Continue with your configuration update
        }
        catch (NumberFormatException e) {
            System.out.println("Please enter a valid integer.");
        }  

        try { 
            detectionConfig = new DetectionConfig(detectionConfig.getIpFailureThreshold(), newTimeThreshold);
            System.out.println("\nConfig updated sucessfully");
        }

        catch (IllegalArgumentException e) {
            System.out.println("Unable to update config: " +e.getMessage());
        }

    }

    public DetectionConfig getDetectionConfig() {
        return detectionConfig;
    }

    
}
