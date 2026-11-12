package com.example.loganalyser.detection;

// import the necessary utils and also time methods
import java.time.Duration;
import java.time.LocalTime;
import java.time.MonthDay;
import java.util.List;

import com.example.loganalyser.model.Alert;
import com.example.loganalyser.model.DetectionRuleType;
import com.example.loganalyser.model.LogEntry;

    //This class provides a common structure and shared functionality for all detection rules. The justification for making it abstract is to enforce a consistent structure while requiring each subclass to implement its own detection logic. This is justified is because it provides the basis and shared functionality of the rules while each subclass can provide the specific detection logic for each rule 
    public abstract class DetectionRule {

    // Stores the rule type, rule name and description to provide context about the suspicious activity being detected. These are stored as private attributes so that they cannot be altered by other classes to encapsulate the fields
    private final DetectionRuleType ruleType;
    private final String ruleName;
    private final String ruleDescription;


    // Constructor initiliases the shared attributes of each detection rule to avoid duplication within the subclasses. This ensures that the subclasses follow a set structure to ensure consistency between rules.
    public DetectionRule (DetectionRuleType ruleType, String ruleName, String ruleDescription) {

        // Ensures that the rule type is not empty and throws an error if it is
        if (ruleType == null) {
            throw new IllegalArgumentException ("Rule type cannot be null");
        }

        // Ensures that the rule name is not empty and throws an error if it is
        if (ruleName == null || ruleName.isBlank()) {
            throw new IllegalArgumentException ("Rule name cannot be blank");
        }

        // Ensures that the rule description is not empty and throws an error if it is
        if (ruleDescription == null || ruleDescription.isBlank()) {
            throw new IllegalArgumentException ("Rule description cannot be blank");
        }

        //Sets the attributes that the object will have once instantiated 
        this.ruleType = ruleType;
        this.ruleName = ruleName;
        this.ruleDescription = ruleDescription;
    }

    // Getters to retrieve rule type, rule name and rule description
    public DetectionRuleType getRuleType() {
        return ruleType;
    }

    public String getRuleName() {
        return ruleName;
    }

    public String getRuleDescription() {
        return ruleDescription;
    }


    // This requires each rule (subclass) to implement its own detection logic. This allows for polymorphism as different rules can be executed with the same method call
    public abstract List<Alert> detect(List<LogEntry> logEntries);
    
    // Checks whether two log events occurred within the configured time window, allowing time-based detection to be reused across rules. This is placed in the parent class as both rules (subclasses) will require this to check if rules are triggered within the time threshold, meaning the shared function can be placed where acessible by both subclasses
    protected boolean isWithinTimeWindow(MonthDay firstDate,LocalTime firstTime,MonthDay lastDate,LocalTime lastTime,int timeThreshold) {

        // Stores the calculated duration between the first and last log events
        Duration duration;

        // Checks whether the logs occured on the same day in the calendar
        if (firstDate.equals(lastDate)) {

            // Rejects the time window if the last event occured before the first, this is used cases such as new years where Jan 1st would come before Dec 31st in the calendar but actually occurs after in the log as the year transitions
            if (lastTime.isBefore(firstTime)) {
                return false;
            }

            // Calculates the time difference between the two events.
            duration = Duration.between(firstTime, lastTime);

        } 
        else {
            // Calculates the expected following date, using 2000 as a reference year because MonthDay does not contain a year and cannot perform date calculations such as adding days without one.
            MonthDay expectedNextDate = MonthDay.from(firstDate.atYear(2000).plusDays(1));

            // Checks whether the last event occurred on the following calendar day, allowing events that cross midnight to be validated without accepting dates further apart. This is needed for log entries that may start at 23:58 and span to 00:02 of the next day for example
            if (expectedNextDate.equals(lastDate)) {

                 // Adds 24 hours to the calculated time difference because the clock has reset to midnight, ensuring the duration represents the actual elapsed time. For example the difference between 23:58 and 00:02 is -23 hours and 56 mins, adding 24 hours ensures the actual difference of 4 minutes is calculated
                duration = Duration.between(firstTime, lastTime).plus(Duration.ofDays(1));

            }
             else {
                // Rejects events that are more than one calendar day apart. This is because the time threshold must be within the same day
                return false;
            }
        }
        // Compares the calculated duration against the configured threshold and returns true if it is within the limit.
        return duration.compareTo(Duration.ofMinutes(timeThreshold)) <= 0;
    }

    // Creates alerts using shared rule information and log event details to avoid duplicated alert construction. The protected access modifier is used as allows only subclasses to reuse this method without exposing it to unrelated classes that could call or alter it.
    protected Alert createAlert(String sourceIp, LogEntry logEntry, int failedAttemptCount) {
        
        // returns a new alert with the necessary parameters to populate an alert
        return new Alert(ruleType, ruleName, sourceIp, ruleDescription, failedAttemptCount, logEntry.getUsername(), logEntry.getDate(), logEntry.getTime(), logEntry.getEventDetails());
    }
}
