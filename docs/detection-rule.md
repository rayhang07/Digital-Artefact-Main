
# Detection Rule Specification

## 1. Purpose

This document defines the initial detection rules for the Java Security Log Analyser. The rules identify potentially suspicious SSH authentication patterns in supplied Linux authentication logs.

The rules are intended to support further investigation. They do not independently establish that an account or system has been compromised.

## 2. Configuration

### 2.1 Configuration File

Detection thresholds and time windows shall be read from a persistent `config.properties` file. Users should be able to change the settings without editing or recompiling the Java source code.

Initial example:

```properties
# Rule 1: repeated failed SSH logins
failed-login-threshold=5
failed-login-window-minutes=5

# Rule 2: successful login following repeated failures
success-after-failures-threshold=5
success-after-failures-window-minutes=5
```

The values shown are initial defaults. Users may change them to suit their analysis needs. For example, setting `failed-login-threshold=3` changes Rule 1 to trigger on three or more failures within the configured time window.

### 2.2 Validation and Defaults

- Thresholds and time windows must be positive integers.
- Missing configuration files and missing or invalid settings must be handled using a documented policy.
- The application must not silently accept zero, negative or non-numeric values.
- The effective configuration should be visible to the user through the use of commands and included in the PDF report where practical.
- Configuration loading and validation should be implemented separately from the detection rules.

The implementation must decide whether an invalid setting causes a clear startup error or whether a documented default is used. The same behaviour must be tested consistently.

## 3. Rule 1 — Repeated Failed SSH Logins

### 3.1 Objective

Identify repeated failed SSH authentication attempts originating from the same source IP address within a configurable time window.

### 3.2 Initial Configuration

| Parameter | Default |
|---|---|
| Event type | Failed SSH authentication |
| Grouping field | Source IP address |
| Threshold | 5 or more failures |
| Time window | 5 minutes |

Both the threshold and time window are configurable in `config.properties`.

### 3.3 Detection Logic

1. Identify supported failed SSH authentication events.
2. Extract each event's timestamp and source IP address.
3. Evaluate failures separately for each source IP address.
4. Use the configured threshold and time window to identify qualifying groups of attempts.
5. Generate an alert when a qualifying window contains at least the configured number of failures from the same IP.
6. Do not count successful authentications as failed attempts.

The implementation must define whether a qualifying burst generates one alert per source IP or separate alerts for distinct qualifying windows.

### 3.4 Alert Information

Where the information is available, an alert should contain:

- Detection rule name.
- Source IP address.
- Number of failed attempts.
- Start and end of the relevant time window.
- Relevant event timestamps.
- Explanation of why the rule triggered.

### 3.5 Example Scenarios

With the default threshold of five failures within five minutes:

**Should trigger:** Five failed authentication attempts from `192.0.2.10` occur within five minutes.

**Should not trigger:** Four failed attempts from `192.0.2.10` occur within five minutes, with no other qualifying attempts.

**Should not trigger:** Three failures from `192.0.2.10` and two from `192.0.2.20` occur, with neither IP independently reaching the threshold.

**Should not trigger:** Five failures from the same IP occur over a period where no five-minute window contains all five attempts.

If the user changes the threshold to three, three failures within the configured window should trigger this rule.

The addresses in these examples are documentation-only example addresses.

## 4. Rule 2 — Successful Login Following Repeated Failures

### 4.1 Objective

Identify a successful SSH authentication preceded by repeated failed authentication attempts from the same source IP address.

### 4.2 Initial Configuration

| Parameter | Default |
|---|---|
| Event types | Failed and successful SSH authentication |
| Grouping field | Source IP address |
| Threshold | 5 or more preceding failures |
| Time window | 5 minutes before the success |

The threshold and time window are configurable independently of Rule 1.

### 4.3 Detection Logic

1. Identify supported failed and successful SSH authentication events.
2. For each successful authentication, examine preceding failed authentication events from the same source IP.
3. Use the configured threshold and time window to determine whether enough failures occurred during the period immediately preceding the successful authentication.
4. Generate an alert if the condition is met.
5. Count only failures occurring before the successful authentication.

### 4.4 Alert Information

Where available, the alert should contain:

- Detection rule name.
- Source IP address.
- Successful authentication timestamp.
- Number of preceding failed attempts.
- Relevant time window.
- Explanation of why the rule triggered.

### 4.5 Example Scenarios

With the default threshold of five preceding failures within five minutes:

**Should trigger:** A source IP records five failed SSH authentication attempts within the five minutes before a successful authentication from that IP.

**Should not trigger:** A successful authentication occurs after only four preceding failures within the relevant window.

**Should not trigger:** Five failures originate from different IP addresses and no individual IP reaches the threshold.

**Should not trigger:** Five failures occur only after the successful authentication.

If the user changes this rule's threshold to three, three preceding failures from the same IP within the configured window should trigger it.

## 5. Shared Rules and Assumptions

### 5.1 Event Processing

- Only recognised and supported authentication events may contribute to detection.
- Malformed or unrecognised lines must not be treated as confirmed failures or successes.
- Missing values must not be invented.
- Event timestamps determine whether events fall within a detection window.
- The implementation must define how missing timestamps, timezone differences and out-of-order events are handled.

### 5.2 Time-Window Boundary

The implementation must define whether an event exactly at the configured window boundary is included. The same interpretation must be used consistently in both detection rules and documented in tests.

### 5.3 Duplicate Alerts

The implementation must define what constitutes a duplicate alert and how repeated qualifying windows are handled. Tests should verify the chosen behaviour.

### 5.4 Limitations

- Multiple legitimate users may share one public IP address through network address translation.
- Users may legitimately make repeated authentication mistakes.
- Lower thresholds may increase false positives; higher thresholds may miss some suspicious patterns.
- Log files may be incomplete or contain unsupported formats.
- Timestamp inconsistencies may affect the analysis.
- The rules identify patterns, not intent.
- An alert requires contextual investigation before conclusions can be drawn.

## 6. Testing Requirements

The following behaviours must be tested:

| Test case | Expected result |
|-----------|-----------------|
| Attempts below the configured threshold | Rule does not trigger |
| Attempts equal to the configured threshold within the window | Rule triggers |
| Attempts with no qualifying window | Rule does not trigger |
| Failures split across multiple IPs | Counts remain separate |
| Success preceded by enough failures from the same IP | Rule 2 triggers |
| Success preceded by fewer than the configured number of failures | Rule 2 does not trigger |
| Failures occurring after the success | Do not count towards Rule 2 |
| Valid custom threshold, such as 3 | Detection follows the custom value |
| Missing configuration file | Documented fallback or clear error occurs |
| Missing configuration setting | Documented default or clear error occurs |
| Zero, negative or non-numeric setting | Rejected or handled by the documented policy |
| Event exactly on the time-window boundary | Matches the documented boundary policy |
| Events provided out of chronological order | Results follow the documented timestamp-processing policy |
| Multiple qualifying windows | Follows the documented duplicate-alert policy |

## 7. Implementation Status

**Status: In requirements phase, moving to implementation**

The rules, configurable settings, defaults and edge-case behaviour must be validated through implementation and automated tests. Any changes made during development should be reflected in this document.
