package com.example.loganalyser.detection;

import com.example.loganalyser.model.DetectionRuleType;

public class DetectionRule {
    private final DetectionRuleType ruleType;
    private final String ruleName;
    private final String ruleDescription;


    public DetectionRule (DetectionRuleType ruleType, String ruleName, String ruleDescription) {

        if (ruleType == null) {
            throw new IllegalArgumentException ("Rule type cannot be null");
        }

        if (ruleName == null || ruleName.isBlank()) {
            throw new IllegalArgumentException ("Rule name cannot be blank");
        }

        if (ruleDescription == null || ruleDescription.isBlank()) {
            throw new IllegalArgumentException ("Rule description cannot be blank");
        }

        this.ruleType = ruleType;
        this.ruleName = ruleName;
        this.ruleDescription = ruleDescription;
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

}
