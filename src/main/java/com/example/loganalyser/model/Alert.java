package com.example.loganalyser.model;
import java.time.LocalTime;
import java.time.MonthDay;

public class Alert {
    private final DetectionRuleType ruleType;
    private final String ruleName;
    private final String sourceIp;
    private final String ruleDescription;
    private final int failedAttemptCount;
    private final String username;
    private final MonthDay date;
    private final LocalTime time;


    public Alert (DetectionRuleType ruleType, String ruleName, String sourceIp, String ruleDescription, int failedAttemptCount, String username, MonthDay date, LocalTime time) {

        if (ruleType == null) {
            throw new IllegalArgumentException("Rule type cannot be empty");
        }

        if (ruleName == null || ruleName.isBlank()) {
            throw new IllegalArgumentException("Rule name cannot be blank");
        }

        if (sourceIp == null || sourceIp.isBlank()) {
            throw new IllegalArgumentException("Source Ip cannot be blank");
        }

        if (ruleDescription == null || ruleDescription.isBlank()) {
            throw new IllegalArgumentException("Rule description cannot be blank");
        }

        if (date == null || time == null) {
            throw new IllegalArgumentException("Date and time cannot blank");
        }

       
        if (failedAttemptCount < 0) {
            throw new IllegalArgumentException("Attempt count cannot be negative");
        }

        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Username cannot be blank");
        }

        this.ruleType = ruleType;
        this.ruleName = ruleName;
        this.sourceIp = sourceIp;
        this.ruleDescription = ruleDescription;
        this.failedAttemptCount = failedAttemptCount;
        this.username = username;
        this.date = date;
        this.time = time;

        
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

   public DetectionRuleType getRuleType() {
    return ruleType;
   }

   public String getRuleName() {
    return ruleName;
   }
   
   public String getRuleDescription() {
    return ruleDescription;
   }

   public int getFailedAttemptCount() {
    return failedAttemptCount;
   }
}
