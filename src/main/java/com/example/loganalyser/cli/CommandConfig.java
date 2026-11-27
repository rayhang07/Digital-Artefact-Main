package com.example.loganalyser.cli;
import java.util.Scanner;

import com.example.loganalyser.config.DetectionConfig;

// This class is utilised to provide the functionality for the config command in order to view or update configuration settings
public class CommandConfig {

    // private field to instantiate a config option for encapsulation
    private DetectionConfig detectionConfig = new DetectionConfig();

    // method to handle the configuration command
    public void handleConfig(Scanner cliScanner) {

        // display banner for config menu and options
        System.out.println("\n============================================================");
        System.out.println("                       CONFIG MENU");
        System.out.println("============================================================");
        System.out.println("View config: see current failure thresholds\n"+ "Set IP failure threshold: set a new IP failure threshold\n" +"Set time failure threshold: set a new time failure threshold\n");
        
        // stores the users input as a string forces it to lowercase to prevent case sensitive issues and trims and leading spaces
        String choice = cliScanner.nextLine().toLowerCase().trim();

        // a switch case is utilised to handle the users inputs as there is a defined set of options therefore each option can be mapped to a separate case with all other cases handled by the default block
        switch (choice) {

            // view config calls the view config method to display existing configuration
            case "view config":
                viewConfig();
                break;

            // set ip failure threshold calls the update ip method to handle updating ip config
            case "set ip failure threshold":
                updateIpConfig(cliScanner);
                break;

            // set time failure threshold calls the update time method to handle updating time config
            case "set time failure threshold":
                updateTimeConfig(cliScanner);
                break;

            // any other inputs lead to an error message
            default:
                System.out.println("Invalid operation");
        }       
    }

    // method to update ip, taking the scanner as a parameter
    public void updateIpConfig(Scanner cliScanner) {

        // prompts user for input
        System.out.println("\nEnter new IP failure threshold");

        // store the current ip threshold 
        int currentIpThreshold = detectionConfig.getIpFailureThreshold();

        // take the users input and store it as a string
        String ipThreshold = cliScanner.nextLine().trim();

        // create a variable to store the new threshold 
        int newIpThreshold;

        // reject empty inputs
        if (ipThreshold.isEmpty()) {
            System.out.println("Unable to update config: IP threshold cannot be empty");
            return;
        }

        // use a try block to parse the user input into an integer, this ensures proper validation of data types
        try {
            newIpThreshold = Integer.parseInt(ipThreshold);
        }

        // if parsing fails, catch an exception and display message that the ip needs to be a valid int, this ensures the user cannot input non numerical values
        catch (NumberFormatException e) {
            System.out.println("\nUnable to update config: IP threshold must be a valid integer");
            return;
        }  

        // if successfully parsed, try to update the config with the new ip but maintain the current time threshold, and display the successful change showing what the threshold has changed to/from
        try {
            detectionConfig = new DetectionConfig(newIpThreshold, detectionConfig.getTimeFailureThreshold());
            System.out.println("\nConfig updated sucessfully IP threshold: " + currentIpThreshold + " -> " + newIpThreshold);
        }
        
        // catch any exceptions to gracefully handle errors and provide the user with an error message to ensure they are aware of the failed operation
        catch (IllegalArgumentException e) {
            System.out.println("\nUnable to update config: " +e.getMessage());
        }
        
    }

    // method to update time, taking the scanner as a parameter
    public void updateTimeConfig(Scanner cliScanner) {

        // prompts user for input
        System.out.println("\nEnter new time failure threshold");

        // store the current time threshold 
        int currentTimeThreshold = detectionConfig.getTimeFailureThreshold();

        // take the users input and store it as a string
        String timeThreshold = cliScanner.nextLine().trim();

        // create a variable to store the new threshold 
        int newTimeThreshold;

        // reject empty inputs
        if (timeThreshold.isEmpty()) {
            System.out.println("\nUnable to update config: Time threshold cannot be empty");
            return;
        }

        // use a try block to parse the user input into an integer, this ensures proper validation of data types
        try {
            newTimeThreshold = Integer.parseInt(timeThreshold);
        }

        // catch any exceptions to gracefully handle errors and provide the user with an error message to ensure they are aware of the failed operation
        catch (NumberFormatException e) {
            System.out.println("\nUnable to update config: Time threshold must be a valid integer");
            return;
        }  

        // if successfully parsed, try to update the config with the new time but maintain the current ip threshold, and display the successful change showing what the threshold has changed to/from
        try { 
            detectionConfig = new DetectionConfig(detectionConfig.getIpFailureThreshold(), newTimeThreshold);
            System.out.println("\nConfig updated sucessfully Time Threshold: " + currentTimeThreshold + " -> " + newTimeThreshold);
        }
 
        // catch any exceptions to gracefully handle errors and provide the user with an error message to ensure they are aware of the failed operation
        catch (IllegalArgumentException e) {
            System.out.println("\nUnable to update config: " +e.getMessage());
        }

    }

    // getter to return the current config
    public DetectionConfig getDetectionConfig() {
        return detectionConfig;
    }

    // method to display current config using getters
    public void viewConfig() {
        System.out.println("\nIP failure threshold: " + detectionConfig.getIpFailureThreshold());
        System.out.println("Time Threshold " + detectionConfig.getTimeFailureThreshold());
    }
    
}
