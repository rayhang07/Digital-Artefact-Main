package com.example.loganalyser.config;

// Stores configurable detection thresholds separately from detection logic to allow flexible rule configuration.
public class DetectionConfig {
 
    // Sets the minimum failed login attempts from one IP required to identify potentially suspicious activity.
    private final int ipFailureThreshold;
    // Sets the maximum time window in minutes to identify concentrated failed login attempts.
    private final int timeFailureThreshold;

    // Constructor to initialise custom thresholds and validates them to prevent invalid detection configurations.
    public DetectionConfig (int ipFailureThreshold, int timeFailureThreshold) {

        // Ensures that the thresholds cannot be negative or 0 for validation purposes
        if (ipFailureThreshold <= 0 || timeFailureThreshold <= 0) {
            throw new IllegalArgumentException ("Threshold must be greater than 0");
        } 

        // Assigns the supplied thresholds to the object's instance variables.
        this.ipFailureThreshold = ipFailureThreshold;
        this.timeFailureThreshold = timeFailureThreshold;
    }

    // Getters to retrieve thresholds
    public int getIpFailureThreshold () {
        return ipFailureThreshold;
    }

    public int getTimeFailureThreshold () {
        return timeFailureThreshold;
    }

    // Provides default thresholds so the detection engine can operate without user configuration.
    public DetectionConfig() {
        this(5, 5);
    }

}
