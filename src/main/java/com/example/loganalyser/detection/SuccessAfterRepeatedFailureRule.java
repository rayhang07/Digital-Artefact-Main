package com.example.loganalyser.detection;
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
public class SuccessAfterRepeatedFailureRule extends DetectionRule {

    // Stores the detection configuration so the rule can access configurable failure and time thresholds.
    private final DetectionConfig detectionConfig;

    // Initialises the rule's identifying information through the parent constructor and stores its configuration for detection.
    public SuccessAfterRepeatedFailureRule(DetectionConfig detectionConfig) {
        super(DetectionRuleType.SUCCESSFUL_LOGIN_AFTER_FAILURES, "Successful Login After Failures","Detects a successful SSH login following repeated failed login attempts");
        this.detectionConfig = detectionConfig;
    }

    // Analyses parsed log entries to identify successful login after repeated failed SSH attempts and returns any resulting security alerts. The override enforces polymorphism ensuring that this detection logic is specific to this rule and can be called by detection rule and engine and will enforce the correct rule
    @Override

    // Method to return a list of alerts triggered by the rule
    public List<Alert> detect(List<LogEntry> logEntries) {

        // Instantiate a new arraylist called alerts
        List<Alert> alerts = new ArrayList<>();

        // Instantiate a new hashpmap that uses key as a string for IP and value as the log entries. The use of a hash map is justified here as it allows for key value pairs to be stored. In this way we can group entries by source IP to see whether one IP appears multiple times and triggers the rules
        Map<String, List<LogEntry>> loginsByIp = new HashMap<>();

        // Loops through the log entries
        for (int i = 0; i < logEntries.size(); i++) {

            // access each element of the list
            LogEntry logEntry = logEntries.get(i);
            
            // Retrieves the source IP address from the current log entry to group login activity by its origin.
            String sourceIp = logEntry.getSourceIp();

            // Checks whether the HashMap already contains an entry for this IP address.
            if (loginsByIp.containsKey(sourceIp)) {

                // Adds the current log entry to the existing list associated with this IP address.
                loginsByIp.get(sourceIp).add(logEntry);
            } 
            else {

                // Creates a new list to store login events when this IP address is encountered for the first time.
                List<LogEntry> logins = new ArrayList<>();

                // Adds the current log entry to the newly created list.
                logins.add(logEntry);

                // Stores the IP address as the key and its associated login events as the value.
                loginsByIp.put(sourceIp, logins);
            }
        }

        // Iterates through each unique IP address so login activity can be analysed independently.
        for (String sourceIp : loginsByIp.keySet()) {

            // Retrieves all login events associated with the current IP address.
            List<LogEntry> logins = loginsByIp.get(sourceIp);

            // Initialises a counter to track consecutive failed login attempts before a successful login.
            int failedAttemptCount = 0;

            // Stores the date of the first failed attempt to establish the starting point of the detection window.
            MonthDay firstAttemptDate = null;

            // Stores the time of the first failed attempt to establish the starting point of the detection window.
            LocalTime firstAttemptTime = null;
           
            // Processes each login event belonging to the current IP address in chronological order.
            for (int i = 0; i < logins.size(); i++) {

                // Retrieves the current login event from the list.
                LogEntry logEntry = logins.get(i);

                // Checks whether the current event represents a failed SSH login attempt.
                if (logEntry.getEventType() == EventType.SSH_LOGIN_FAILURE) {

                    // Increments the failure counter to track the number of unsuccessful login attempts.
                    failedAttemptCount++;

                    // Identifies the first failure so its date and time can be recorded as the detection window's starting point.
                    if (failedAttemptCount == 1) {

                        // Records the date of the first failed login attempt.
                        firstAttemptDate = logEntry.getDate();

                        // Records the time of the first failed login attempt.
                        firstAttemptTime = logEntry.getTime();
                    }

                }

                // Checks whether the current event is a successful login and the IP has reached the configured failure threshold.
                else if (logEntry.getEventType() == EventType.SSH_LOGIN_SUCCESS && failedAttemptCount >= detectionConfig.getIpFailureThreshold()) { 

                    // Checks that the successful login occurred within the configured time window
                    if (isWithinTimeWindow(firstAttemptDate, firstAttemptTime, logEntry.getDate(), logEntry.getTime(), detectionConfig.getTimeFailureThreshold())) {

                        // If so creates a new alert and adds it to the alert list
                        Alert alert = createAlert(sourceIp, logEntry, failedAttemptCount);
                        alerts.add(alert);
                    }

                    // Reset after a successful login
                    failedAttemptCount = 0;
                    firstAttemptDate = null;
                    firstAttemptTime = null;
                }
            }
        }

        // Returns the list of alerts for reporting
        return alerts;
    }

}