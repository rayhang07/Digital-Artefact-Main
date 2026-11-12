package com.example.loganalyser.model;
import java.time.LocalTime;
import java.time.MonthDay;
import java.util.Objects;

// This class is used to define an alert and its attributes
public class Alert {

    // Stores the type of detection rule that generated the alert to identify the category of suspicious activity.
    private final DetectionRuleType ruleType;

    // Stores the name of the detection rule to make the alert identifiable to users.
    private final String ruleName;

    // Stores the associated IP address to identify the source of the suspicious activity.
    private final String sourceIp;
    
    // Stores a description of the detection rule to provide context about why the alert was generated.
    private final String ruleDescription;

    // Stores the number of failed login attempts associated with the alert to provide additional security context.
    private final int failedAttemptCount;

    // Stores the username involved in the suspicious activity to identify the targeted account.
    private final String username;

    // Stores the date of the relevant login event using MonthDay because SSH logs may not contain year information.
    private final MonthDay date;

    // Stores the time of the relevant login event to provide a timestamp for the alert.
    private final LocalTime time;

    private final String eventDetails;

    // Constructor to initialise an alert with the relevant detection rule and login event information, ensuring each alert contains the details needed for reporting.
    public Alert (DetectionRuleType ruleType, String ruleName, String sourceIp, String ruleDescription, int failedAttemptCount, String username, MonthDay date, LocalTime time, String eventDetails) {

        // Validates the rule type to prevent alerts from being created without an identifiable detection category.
        if (ruleType == null) {
            throw new IllegalArgumentException("Rule type cannot be empty");
        }

        // Ensures the rule name is provided so alerts can be identified in reports.
        if (ruleName == null || ruleName.isBlank()) {
            throw new IllegalArgumentException("Rule name cannot be blank");
        }

        // Ensures the source IP is provided because it identifies where the suspicious activity originated.
        if (sourceIp == null || sourceIp.isBlank()) {
            throw new IllegalArgumentException("Source Ip cannot be blank");
        }

        // Ensures a description is provided so users can understand why the detection rule triggered.
        if (ruleDescription == null || ruleDescription.isBlank()) {
            throw new IllegalArgumentException("Rule description cannot be blank");
        }

        // Ensures both date and time are available so the alert can identify when the relevant event occurred.
        if (date == null || time == null) {
            throw new IllegalArgumentException("Date and time cannot blank");
        }

        // Prevents negative attempt counts because they cannot represent a valid number of failed logins.
        if (failedAttemptCount < 0) {
            throw new IllegalArgumentException("Attempt count cannot be negative");
        }

        // Ensures the username is provided to identify the account involved in the login activity.
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Username cannot be blank");
        }

        // Assigns the validated constructor parameters to the object's fields
        this.ruleType = ruleType;
        this.ruleName = ruleName;
        this.sourceIp = sourceIp;
        this.ruleDescription = ruleDescription;
        this.failedAttemptCount = failedAttemptCount;
        this.username = username;
        this.date = date;
        this.time = time;
        this.eventDetails = eventDetails;

        
    }

    // Overrides the equals methods so that when comparing an alert to the list of alerts, we can see if it already exists in the list to avoid duplicates
    @Override
    public boolean equals(Object object) {

        // Checks whether both references point to the same object
        if (this == object) {
            return true;
        }

        // Checks whether the object is null or a different class.
        if (object == null || getClass() != object.getClass()) {
            return false;
        }

        // Converts the object into an Alert so its fields can be compared.
        Alert alert = (Alert) object;

        // Compares the identifying fields to determine whether the alerts are duplicates.
        return ruleType == alert.ruleType && Objects.equals(sourceIp, alert.sourceIp) && Objects.equals(username, alert.username) && Objects.equals(date, alert.date) && Objects.equals(time, alert.time);
    }


    // Generates a hash code using the same identifying fields as equals(). This is good practice to override whenever overriding equals to ensure that duplicates or equal alert objects generate the same hashcode
    @Override
    public int hashCode() {
        return Objects.hash(ruleType, sourceIp, username, date, time);
    }

    // Getter methods to retrieve sourceip
    public String getSourceIp() {
        return sourceIp;
    }

    // Getter methods to retrieve username
    public String getUsername() {
        return username;
    }

    // Getter methods to retrieve date
    public MonthDay getDate() {
        return date;
    }

    // Getter methods to retrieve time
    public LocalTime getTime() {
        return time;
    }

    // Getter methods to retrieve rule type
    public DetectionRuleType getRuleType() {
        return ruleType;
    }

    // Getter methods to retrieve rule name
    public String getRuleName() {
        return ruleName;
    }
    
    // Getter methods to retrieve rule description
    public String getRuleDescription() {
        return ruleDescription;
    }

    // Getter method to retrieve the failed attempt count
    public int getFailedAttemptCount() {
        return failedAttemptCount;
    }

    // Getter to return event details for alerts
    public String getEventDetails() {
        return eventDetails;
    }
}
