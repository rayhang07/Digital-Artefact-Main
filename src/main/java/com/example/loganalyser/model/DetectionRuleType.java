package com.example.loganalyser.model;


// enum to define the two types of rules. The use of enum was justified as it allows for values to be restricted into predefined categories, which is needed to ensure that the event types are consistent and valid throughout the application. A bool was not chosen as it would be less descriptive and less extensible if more events were to be added.
public enum DetectionRuleType {
    REPEATED_FAILED_SSH_LOGINS,
    SUCCESSFUL_LOGIN_AFTER_FAILURES,
}
