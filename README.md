# Java Security Log Analyser

## Overview

The Java Security Log Analyser is a command-line application developed in Java 17 that analyses Linux SSH authentication logs to identify potentially suspicious login activity.

It parses authentication log entries, identifies relevant events and applies configurable detection rules to highlight patterns that may indicate suspicious behaviour.

The application produces alerts and PDF reports containing information about detected activity, allowing users to review authentication events and investigate potential security concerns.

This project was developed to demonstrate practical application of Java programming, file parsing, object-oriented design, automated testing and security event analysis.

## Features

- **SSH log parsing:** Processes Linux SSH authentication logs and extracts relevant information, including timestamps, usernames, source IP addresses and authentication details.
- **Malformed entry handling:** Identifies malformed and unrecognised log entries rather than allowing individual parsing errors to stop the analysis.
- **Detection rules:** Identifies repeated authentication failures and successful logins following repeated failures.
- **Configurable thresholds:** Allows detection thresholds to be adjusted through the application's configuration functionality.
- **Alert generation:** Produces alerts containing information about detected activity and the associated log evidence.
- **PDF reporting:** Generates structured PDF reports containing detected alerts.
- **Analysis summaries:** Provides statistics about processed, malformed, unrecognised and other SSH log entries.

## Requirements

- Java 17 runtime.
- The Java Security Log Analyser executable JAR.
- A compatible Linux SSH authentication log file to analyse.

The application can run on Windows and Linux. A separate application build is not required for each operating system.

## Downloading the Application

Download the latest release from the project's GitHub Releases page.

The release contains the executable JAR file required to run the application.

You do not need to download the source code or install Maven to use the released application.

## Running the Application

### Windows

1. Install Java 17 if it is not already installed.
2. Download the executable JAR from GitHub Releases.
3. Open PowerShell or Command Prompt.
4. Navigate to the directory containing the downloaded JAR.
5. Run the following command:

```powershell
java -jar java-security-log-analyser-1.0.0.jar
```

### Linux

1. Install a Java 17 runtime if it is not already installed.
2. Download the executable JAR from GitHub Releases.
3. Open a terminal.
4. Navigate to the directory containing the downloaded JAR.
5. Run:

```bash
java -jar java-security-log-analyser-1.0.0.jar
```

For Debian-based distributions, Java 17 can be installed using:

```bash
sudo apt update
sudo apt install openjdk-17-jre
```

### Checking Your Java Installation

To check whether Java is installed, run:

```bash
java -version
```

The installed Java runtime must be compatible with the version used to build the application.

## Using the Application

After launching the JAR, interact with the command-line interface to access the available functionality.

The application supports the following operations:

| Operation     | Description                                                                         |
| ------------- | ----------------------------------------------------------------------------------- |
| Analyse       | Processes the selected SSH authentication log file and applies the detection rules. |
| Configuration | Views or updates the detection thresholds.                                          |
| Alerts        | Displays the alerts generated during analysis.                                      |
| Report        | Generates a PDF report containing the detected alerts.                              |
| Summary       | Displays statistics about the processed log entries.                                |
| Exit          | Closes the application.                                                             |

The application requires the user to provide the relevant log file and configuration information where requested.

## Detection Rules

The application currently implements two detection rules.

### Repeated Authentication Failures

Identifies repeated failed authentication attempts from a source IP address when the configured threshold is reached.

### Successful Login After Repeated Failures

Identifies a successful login following repeated authentication failures, which may warrant further investigation.

Both rules use configurable thresholds to determine when an alert should be generated.

## Limitations

The application has been designed as a focused SSH log analysis tool. It does not provide the functionality of a full Security Information and Event Management (SIEM) platform.

Current limitations include:

- **SSH logs only:** The application is designed for the supported Linux SSH authentication log format. It is not a general-purpose log analyser.
- **No real-time monitoring:** Logs are analysed when supplied to the application. It does not continuously monitor systems or collect events in real time.
- **No remote log collection:** Users must provide the log files themselves. The application does not automatically retrieve logs from remote machines.
- **Limited detection coverage:** Detection is based on the implemented rules and configured thresholds. It does not identify every possible attack or suspicious activity.
- **No automated incident response:** Alerts are generated for investigation, but the application does not block IP addresses, terminate sessions or take action against suspected attackers.
- **No graphical interface:** The application uses a command-line interface.
- **No persistent central database:** The application does not provide a central database for storing and correlating events across multiple systems.
- **Alerts are indicators, not proof:** A generated alert identifies activity that may be suspicious. It does not independently confirm that a system has been compromised.

## Technologies Used

- Java 17
- Maven
- JUnit 5
- Git and GitHub
- GitHub Actions
- GitHub CodeQL
- OWASP Dependency-Check
- PDF generation using OpenPDF/iText-compatible libraries

## Building from Source

If you want to build the application yourself, clone the repository and use the Maven Wrapper.

**Windows:**

```powershell
.\mvnw.cmd clean verify
```

**Linux:**

```bash
./mvnw clean verify
```

To package the application:

**Windows:**

```powershell
.\mvnw.cmd package
```

**Linux:**

```bash
./mvnw package
```

The generated executable JAR will be available in the `target` directory.

## Testing and Quality Assurance

The project includes automated unit tests using JUnit 5 to verify parsing, detection rules, configuration handling and other application functionality.

Manual integration and end-to-end testing is also used to verify the overall application workflow, including log analysis, alert generation, PDF reporting and summary output.

GitHub Actions is used to automate the build and verification process. Security tooling includes CodeQL analysis and OWASP Dependency-Check.

## Project Scope

This project focuses on demonstrating how security-relevant log data can be parsed, processed and analysed using Java.

It provides a foundation for understanding authentication event analysis, rule-based detection and security reporting. It is an educational project and is not intended to replace an enterprise monitoring or incident response platform.
