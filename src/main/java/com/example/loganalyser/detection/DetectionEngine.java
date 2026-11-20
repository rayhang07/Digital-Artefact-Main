package com.example.loganalyser.detection;

// Import necessary utils and packages
import java.util.ArrayList;
import java.util.List;

import com.example.loganalyser.config.DetectionConfig;
import com.example.loganalyser.model.Alert;
import com.example.loganalyser.model.LogEntry;

// This class is used to coordinate and execute the detection rules against entries. The justification for this is to separate the responsibility between the rules which define the structure of rules
public class DetectionEngine {
    
    // Coordinates the execution of detection rules and centralises alert collection.
    private final List<DetectionRule> detectionRules;

    // Stores the configuration shared with detection rules to maintain consistent detection thresholds.
    private final DetectionConfig detectionConfig;


    // Initialises the detection engine with a configuration and registers the default detection rules.
    public DetectionEngine (DetectionConfig detectionConfig) {

        // Initialises engine with the shared config and also the detection rules list
        this.detectionConfig = detectionConfig;
        this.detectionRules = new ArrayList<>();

        // Adds the default rules to our detection rules list to populate it with the 2 rules we need to detect against
        defaultRules();

    }

    // Executes every registered detection rule and combines their results into a single alert collection. This allows for alerts to be displayed and utilised
    public List<Alert> detect(List<LogEntry> logEntries) {

        // Instantiates a new alerts array list
        List<Alert> alerts = new ArrayList<>();
        // Iterate through the rules and calls the detect method to detect any instances of the rules being triggered and adds them to the alerts array list
        for (DetectionRule rule : detectionRules) {
            alerts.addAll(rule.detect(logEntries));
        }

        // returns the alerts array list for use
        return alerts;
    }

    // Method to establish the default rules to define which suspicious activities can be identified
    private void defaultRules() {

        // Creates a repeated failure rule to detect multiple failed SSH login attempts from the same IP address. 
        DetectionRule repeatedFailedSshRule = new RepeatedFailureRule(detectionConfig);        

        // Adds the rule to the rules list with the engine so it is included in detection.
        detectionRules.add(repeatedFailedSshRule);

        // Creates a successful login rule to identify successful SSH logins following repeated failures.
        DetectionRule successfulLoginAfterFailuresRule = new SuccessAfterRepeatedFailureRule(detectionConfig);

        // Adds the rule to the rules list with the engine so it is included in detection.
        detectionRules.add(successfulLoginAfterFailuresRule);
    }

    // Getter to return the rules list
    public List<DetectionRule> getDetectionRules() {
        return new ArrayList<>(detectionRules);
    }
}
