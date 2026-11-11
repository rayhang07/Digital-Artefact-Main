package com.example.loganalyser.detection;
import java.util.ArrayList;
import java.util.List;

import com.example.loganalyser.config.DetectionConfig;
import com.example.loganalyser.model.DetectionRuleType;


public class DetectionEngine {
    private final List<DetectionRule> detectionRules;
    private final DetectionConfig detectionConfig;

    public DetectionEngine (DetectionConfig detectionConfig) {
        this.detectionConfig = detectionConfig;
        this.detectionRules = new ArrayList<>();
        defaultRules();

    }

    private void defaultRules() {
        DetectionRule repeatedFailedSshRule = new DetectionRule(DetectionRuleType.REPEATED_FAILED_SSH_LOGINS, "Repeated Failed SSH Logins", "Detects repeated failed SSH attempts from one IP");
        detectionRules.add(repeatedFailedSshRule);
        DetectionRule successfulLoginAfterFailuresRule = new DetectionRule(DetectionRuleType.SUCCESSFUL_LOGIN_AFTER_FAILURES, "Successful Login After Repeated Failures", "detects a successful SSH login following repeated failed attempts from the same source IP");
        detectionRules.add(successfulLoginAfterFailuresRule);
    }

    public List<DetectionRule> getDetectionRules() {
        return new ArrayList<>(detectionRules);
    }
}
