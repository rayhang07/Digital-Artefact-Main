package com.example.loganalyser.detection;

// import all necessary packages
import java.time.LocalTime;
import java.time.MonthDay;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.example.loganalyser.config.DetectionConfig;
import com.example.loganalyser.model.Alert;
import com.example.loganalyser.model.DetectionRuleType;
import com.example.loganalyser.model.EventType;
import com.example.loganalyser.model.LogEntry;


// This class provides the logic for detecting this specific rule. The use of inheritance is justified as it allows the subclass to make use of detection rule constructor while providing its own specific logic and fields for the rule.
public class RepeatedFailureRule extends DetectionRule {

    // Stores the detection configuration so the rule can access configurable failure and time thresholds.
    private final DetectionConfig detectionConfig;

    // Initialises the rule's identifying information through the parent constructor and stores its configuration for detection.
    public RepeatedFailureRule(DetectionConfig detectionConfig) {
        super(DetectionRuleType.REPEATED_FAILED_SSH_LOGINS, "Repeated Failed SSH Logins", "Detects repeated failed SSH attempts from one IP");
        this.detectionConfig = detectionConfig;
    }

    // Analyses parsed log entries to identify repeated failed SSH attempts and returns any resulting security alerts. The override enforces polymorphism ensuring that this detection logic is specific to this rule and can be called by detection rule and engine and will enforce the correct rule
    @Override

    // Method to return a list of alerts triggered by the rule
    public List<Alert> detect(List<LogEntry> logEntries) {

        // Instantiate a new arraylist called alerts
        List<Alert> alerts = new ArrayList<>();

        // Instantiate a new hashpmap that uses key as a string for IP and value as the log entries. The use of a hash map is justified here as it allows for key value pairs to be stored. In this way we can group entries by source IP to see whether one IP appears multiple times and triggers the rules
        Map<String, List<LogEntry>> failedLoginsByIp = new HashMap<>();

        // Loops through the log entries
        for (int i = 0; i < logEntries.size(); i++) {
            // access each element of the list
            LogEntry logEntry = logEntries.get(i);

            // if the element has event type of a login failure store its source IP
            if (logEntry.getEventType() == EventType.SSH_LOGIN_FAILURE) {
                String sourceIp = logEntry.getSourceIp();

                // if our hashmap already contains that IP, add the entry to the value of that specific IP
                if (failedLoginsByIp.containsKey(sourceIp)) {
                    failedLoginsByIp.get(sourceIp).add(logEntry);
                } 
                else {
                    // if the hashmap doesnt contain the IP, instantiate a new list of failed logins and add the entry
                    List<LogEntry> failedLogins = new ArrayList<>();
                    failedLogins.add(logEntry);
                    // put both the source IP and list of failed logins into our hashmap as key value pairs
                    failedLoginsByIp.put(sourceIp, failedLogins);
                }
            }
        }

        // Loop through each unique IP in the hashmap keys to analyse the failed logins associated with it
        for (String sourceIp : failedLoginsByIp.keySet()) {

            // Retrieves the list of failed login entries associated with the current IP address.
            List<LogEntry> failedLogins = failedLoginsByIp.get(sourceIp);

            // Initialises a counter to track the number of failed attempts from the current IP.
            int failedAttemptCount = 0;

            // Initialises the date of the first failure as null because no attempts have been processed yet.
            MonthDay firstAttemptDate = null;

             // Initialises the time of the first failure as null because no attempts have been processed yet.
            LocalTime firstAttemptTime = null;

            // Iterates through each failed login entry associated with the current IP address.
            for (int i = 0; i < failedLogins.size(); i++) {

                // Retrieves the current log entry using its position in the list.
                LogEntry logEntry = failedLogins.get(i);

                // Increments the counter to track the number of failed login attempts processed.
                failedAttemptCount++;

                // Record the first failure in the batch so its date and time can be used to validate the time window for the threshold to trigger the rule
                if (failedAttemptCount == 1) {

                    // Records the date of the first failed login attempt.
                    firstAttemptDate = logEntry.getDate();

                    // Records the time of the first failed login attempt.
                    firstAttemptTime = logEntry.getTime();
                }

                // Check when the failure threshold is reached
                if (failedAttemptCount == detectionConfig.getIpFailureThreshold()) {

                    // if so check if it is within the time threshold
                    if (isWithinTimeWindow(firstAttemptDate,firstAttemptTime,logEntry.getDate(),logEntry.getTime(),detectionConfig.getTimeFailureThreshold())) {

                        // Create a new alert if both are true and add it to the alerts list
                        Alert alert = createAlert(sourceIp, logEntry,failedAttemptCount);
                        alerts.add(alert);
                    }

                    // Reset for the next batch 
                    failedAttemptCount = 0;
                    firstAttemptDate = null;
                    firstAttemptTime = null;
                }
            }
        }

        // return the alerts list for reporting
        return alerts;
    }

   

    
}