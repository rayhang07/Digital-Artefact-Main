
# Java Security Log Analyser — Requirements

## 1. Project Overview

### 1.1 Purpose

The Java Security Log Analyser is a command-line application designed to analyse supplied Linux SSH authentication logs and identify potentially suspicious authentication patterns.

The application will parse supported log entries, identify repeated failed login attempts and detect successful logins preceded by repeated failures. It will display analysis results in the terminal and generate a structured PDF report.

Users will be able to configure detection thresholds and time windows in a persistent configuration file without modifying or recompiling the Java source code.

The tool is intended for educational and investigative support. Its alerts indicate patterns that may warrant further investigation and do not prove that malicious activity has occurred.

### 1.2 Target Users

The intended users are students, junior cybersecurity practitioners and IT administrators who want to examine authentication logs without manually reviewing every entry.

The application will analyse local log files rather than collect logs from remote systems or monitor activity in real time.

## 2. Functional Requirements

### 2.1 Input Handling

- **FR-01:** The application shall accept a path to a supported authentication log file.
- **FR-02:** The application shall check whether the specified file can be accessed.
- **FR-03:** The application shall provide a clear error message when the file is missing, inaccessible or invalid.
- **FR-04:** The application shall handle empty input files without crashing.
- **FR-05:** The application shall not modify the original log file.

### 2.2 Log Parsing

- **FR-06:** The application shall read the input file and process its entries.
- **FR-07:** The application shall identify supported failed and successful SSH authentication events.
- **FR-08:** The parser shall extract relevant fields where available, including timestamps, usernames, source IP addresses and event types.
- **FR-09:** The application shall distinguish recognised events from malformed or unsupported entries.
- **FR-10:** A malformed or unsupported entry shall not automatically be treated as a failed or successful login.
- **FR-11:** The application shall continue processing valid entries when individual lines cannot be parsed.
- **FR-12:** The analysis results shall include counts of processed, malformed and unrecognised entries where these can be determined.

### 2.3 Configuration

- **FR-13:** The application shall load detection settings from a persistent configuration file named `config.properties`.
- **FR-14:** The configuration file shall allow users to set the failed-login threshold and its time window.
- **FR-15:** The configuration file shall allow users to set the threshold and time window for successful logins preceded by repeated failures.
- **FR-16:** Users shall be able to change these settings without modifying or recompiling the Java source code.
- **FR-17:** The application shall validate configuration values, including requiring thresholds and time windows to be positive integers.
- **FR-18:** The application shall handle missing configuration files and invalid or missing settings predictably, using documented defaults or reporting a clear configuration error.
- **FR-19:** The application shall make the active configuration visible to the user, such as through a CLI command or analysis summary.
- **FR-20:** The application should record the effective thresholds and time windows in the PDF report so that results can be interpreted and reproduced.
- **FR-21:** The application shall separate configuration loading and validation from detection logic.

### 2.4 Threat Detection

- **FR-22:** The application shall detect repeated failed SSH authentication attempts from the same source IP address.
- **FR-23:** The initial default threshold shall be five or more failures within a five-minute window.
- **FR-24:** Failed attempts from different source IP addresses shall be evaluated separately.
- **FR-25:** The application shall detect a successful SSH authentication preceded by a configurable number of failed attempts from the same source IP within a configurable preceding time window.
- **FR-26:** The initial default for the second rule shall be five preceding failures within five minutes.
- **FR-27:** Detection shall use parsed event timestamps rather than relying solely on the order of lines in the file.
- **FR-28:** Each alert shall identify the applicable rule and provide supporting information, such as the source IP, relevant timestamps, attempt count and reason for the alert, where available.
- **FR-29:** The application shall describe alerts as potentially suspicious activity rather than confirmed compromises.
- **FR-30:** Detection rules shall be organised so additional rules can be introduced without rewriting the entire application.

### 2.5 Command-Line Interface

- **FR-31:** The application shall provide instructions for using its commands.
- **FR-32:** The application shall support analysis of a supplied log file.
- **FR-33:** The application shall display a summary of the analysis.
- **FR-34:** The application shall display generated alerts and their supporting details.
- **FR-35:** The application shall generate a PDF report at a specified output location.
- **FR-36:** The application should provide information about available detection rules and active configuration settings if time permits.

### 2.6 PDF Reporting

- **FR-37:** The application shall generate a structured PDF report from the analysis results.
- **FR-38:** The report shall include the input filename and the time at which the analysis was performed.
- **FR-39:** The report shall include summary statistics and the number of alerts generated.
- **FR-40:** The report shall include an alert table containing relevant details, such as the rule name, source IP, timestamp, severity if implemented, and explanation.
- **FR-41:** The report shall identify malformed or unrecognised entries where applicable.
- **FR-42:** The report should include the effective detection thresholds and time windows used for the analysis.
- **FR-43:** The report shall explain the tool's limitations and clarify that alerts are not proof of malicious activity.
- **FR-44:** The application shall report errors encountered while creating or saving the PDF.
- **FR-45:** PDF generation shall be separated from log parsing and detection logic.

### 2.7 Testing

- **FR-46:** The application shall include automated unit tests using JUnit.
- **FR-47:** Tests shall cover valid log entries, malformed entries and empty input.
- **FR-48:** Tests shall cover missing or inaccessible input files where practical.
- **FR-49:** Detection tests shall cover values below, at and above the configured threshold.
- **FR-50:** Tests shall verify that attempts from different IP addresses are not incorrectly combined.
- **FR-51:** Tests shall cover configured time-window boundaries.
- **FR-52:** Tests shall cover successful logins preceded by sufficient and insufficient failed attempts.
- **FR-53:** Tests shall cover missing configuration files, missing settings, invalid numbers, zero and negative values, and valid custom thresholds.
- **FR-54:** Tests shall verify that changing a configuration value changes detection behaviour as expected.
- **FR-55:** Tests shall cover out-of-order timestamps and duplicate alert behaviour once the implementation rules have been defined.

## 3. Non-Functional Requirements

### 3.1 Reliability

The application should handle expected input errors without terminating unexpectedly. Invalid entries should not prevent valid entries from being analysed. Invalid configuration must not silently result in unintended detection behaviour.

### 3.2 Maintainability

The application shall use clearly named classes, methods and packages as well as comments justifying choices. Parsing, configuration, detection, command-line interaction and report generation should have distinct responsibilities.

### 3.3 Security

The application shall treat log contents and configuration values as untrusted input. It shall not execute commands or interpret log entries as executable instructions. Development and testing shall use fictional or sanitised sample data.

### 3.4 Usability

The application shall provide understandable command-line output and actionable error messages. The PDF report shall organise findings so a reader can understand what was detected and why. The active configuration and its defaults shall be documented.

### 3.5 Version Control

Git shall be used to track development. Commits should represent meaningful changes, and the repository should include a README explaining the project, setup, usage and limitations.

## 4. Constraints and Assumptions

- The application will be written in Java.
- Maven will manage the project build and dependencies.
- JUnit will be used for automated testing.
- Git and GitHub will be used for version control.
- The initial interface will be command-line based.
- The initial input format will be Linux SSH authentication logs; the exact supported formats will be documented separately.
- The initial default threshold for each rule will be five failures within five minutes.
- Users will be able to change thresholds and time windows in `config.properties`.
- The policy for missing or invalid configuration will be explicitly documented and tested.
- A PDF library will be selected after reviewing its suitability and licensing requirements.
- Development time is limited, so optional features must not compromise the core parser, detection rules, tests or report generation.

## 5. Out of Scope

The initial version will not include:

- Real-time monitoring.
- Remote log collection.
- Automatic IP blocking or incident response.
- A graphical user interface.
- A database.
- Machine-learning-based threat detection.
- Windows event logs or unrelated log formats.
- Claims that detected activity confirms an account compromise.

Containerisation with Docker is a potential extension if the core application is complete and tested.

## 6. Acceptance Criteria

The project will be considered complete when:

1. The application builds successfully using Maven.
2. A user can supply a supported authentication log file.
3. Supported authentication events are parsed into structured data.
4. Malformed and unrecognised entries are handled without crashing the application.
5. The application loads and validates configuration settings.
6. Users can change detection thresholds and time windows without changing Java source code.
7. Missing or invalid configuration is handled according to the documented policy.
8. Repeated failed logins are detected according to the active threshold and time window.
9. Successful logins preceded by sufficient failures can trigger the second detection rule.
10. Attempts from different source IP addresses are evaluated separately.
11. The user can view an analysis summary and generated alerts.
12. A structured PDF report can be generated and, where implemented, includes the effective configuration.
13. Invalid input paths and report-generation errors produce understandable messages.
14. Automated tests cover the main parsing, configuration and detection behaviours.
15. The README documents setup, configuration, commands, limitations and examples.
16. The repository contains a meaningful development history and documentation that accurately reflects implemented features.

Requirements may be refined during development. Any changes to supported formats, configuration policy, thresholds or expected behaviour should be documented and reflected in the tests.
