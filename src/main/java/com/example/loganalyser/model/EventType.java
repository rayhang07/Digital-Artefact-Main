package com.example.loganalyser.model;

// Enum to represent the different types of events that can be logged in the system. The use of enum was justified as it allows for values to be restricted into predefined categories, which is needed to ensure that the event types are consistent and valid throughout the application. A bool was not chosen as it would be less descriptive and less extensible if more events were to be added.
public enum EventType {
    SSH_LOGIN_SUCCESS,
    SSH_LOGIN_FAILURE,
}

