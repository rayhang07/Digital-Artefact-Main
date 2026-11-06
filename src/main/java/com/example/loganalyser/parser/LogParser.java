// package declaration for the LogParser class, which is part of the com.example.loganalyser.parser package. 
package com.example.loganalyser.parser;

// Import the necessary classes from the com.example.loganalyser.model package to represent log entries and parse results. 
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalTime;
import java.time.MonthDay;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import com.example.loganalyser.model.EventType;
import com.example.loganalyser.model.LogEntry;
import com.example.loganalyser.model.ParseResult;

// The LogParser class is responsible for parsing log files and extracting relevant information from log entries. It provides methods to determine if a log entry is an SSH log entry, parse a log file, determine the event type of a log entry, and extract various pieces of information from a log entry, such as the source IP, username, date, time, authentication method, source port, and SSH protocol. The class also handles exceptions that may occur during parsing and provides appropriate error messages.
public class LogParser {
    
    // Method to determine if a log entry is an SSH log entry, this will be called from the parseLogFile method in the LogParser class. This is justified as it allows for separating analysis logic from validation logic.
    private boolean isSshLogEntry(String logEntry) {

        // Check if the log entry is null or blank, if so return false. This allows for handling user input that may be empty or null, which can cause issues when trying to access the log file.
        if (logEntry == null || logEntry.isBlank()) {
            return false;
        }

        // Check if the log entry contains "sshd" and any of the following keywords: "Failed password", "Accepted password", "Failed publickey", "Accepted publickey", "Failed keyboard-interactive", "Invalid user", or "Accepted keyboard-interactive". If so return true, otherwise return false. This allows for identifying SSH log entries based on specific keywords that are commonly found in SSH log entries.
        else if (logEntry.contains("sshd")) {
            return true;
        }
        
        // If the log entry does not contain "sshd" or any of the specified keywords, return false. This allows for identifying non-SSH log entries based on the absence of specific keywords that are commonly found in SSH log entries.
        return false;   
    }

   
    // Method to parse a log file and extract relevant information from log entries, this will be called from the handleAnalysis method in the CommandAnalysis class. This is justified as it allows for separating analysis logic from validation logic.
    public ParseResult parseLogFile(Path logFilePath) throws IOException {
        
        // Create lists to store log entries, malformed entries, and unrecognised entries. This allows for categorising log entries based on their validity and recognisability, which can be useful for analysis and reporting purposes. They are created as new ArrayLists rather than static arrays to allow for dynamic resizing and to avoid potential issues with fixed-size arrays, such as running out of space or wasting memory. Additionally new ArrayLists ensure that lists dont share the same reference, which could lead to unintended modifications and data inconsistencies.
        List<LogEntry> logEntries = new ArrayList<>();
        List<String> malformedEntries = new ArrayList<>();
        List<String> unrecognisedEntries = new ArrayList<>();
        List<String> otherSSHEntries = new ArrayList<>();
        EventType eventType;

        // try block is used to handle any IOExceptions that may occur when reading the log file. This allows for graceful error handling and prevents the program from crashing due to unhandled exceptions.
        try (BufferedReader reader = Files.newBufferedReader(logFilePath)) {

            // Create string variable to store each line of the log file
            String line;

            // uses a loop to read each line of the file. A while loop is used over a for loop as it allows for reading the file until a condition is met (in this case the end of the file). This also allows for handling files of unknown lengths as the loop continues until there are no more lines to read rather than a fixed numebr of iterations.
            while ((line = reader.readLine()) != null) {

                // Check if the line is blank, if so skip it. This allows for handling log files that may contain empty lines, which can cause issues when trying to access the log file.
                if (line.isBlank()) {
                    continue; 
                }
                // Check if the line meets criteria for an SSH log entry, if not add it to unrecognised entries and skip it. This allows for identifying and categorising log entries based on keywords which can be useful for analysis and reporting
                if (!isSshLogEntry(line)) {
                    unrecognisedEntries.add(line);
                    continue; 
                }

            try {
                eventType = determineEventType(line);
            } 
            catch (IllegalArgumentException e) {
                otherSSHEntries.add(line);
                continue;
            }
            
            // Try to create a new LogEntry object from the line, if it fails add it to malformed entries and skip it. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file.        
            try {
                LogEntry logEntry = new LogEntry(determineEventType(line), extractSourceIp(line), extractUsername(line), extractDate(line), extractTime(line), eventDetails(line));
                logEntries.add(logEntry);
            }

            // Catch any IllegalArgumentException or DateTimeParseException that may occur when creating a new LogEntry object, add the line to malformed entries and skip it. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file.
            catch (IllegalArgumentException | DateTimeParseException e) {
                malformedEntries.add(line);
                continue;
            }

    

            }
        }      
    
        // Return a new ParseResult object containing the lists of log entries, malformed entries, and unrecognised entries. This allows for returning the results of the parsing operation in a structured and organised manner, which can be useful for analysis and reporting purposes.
        return new ParseResult(logEntries, malformedEntries, unrecognisedEntries, otherSSHEntries);

    }

    // Method to determine the event type of a log entry, this will be called from the parseLogFile method in the LogParser class. This is justified as it allows for separating analysis logic from validation logic.
    public EventType determineEventType(String logEntry) {

        // Check if the log entry is null or blank, if so throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file.
        if (logEntry == null || logEntry.isBlank()) {
            throw new IllegalArgumentException("Log entry cannot be null or blank");
        } 
        // Check if the log entry contains "Accepted", if so return EventType.SSH_LOGIN_SUCCESS. This allows for identifying successful SSH login attempts based on specific keywords that are commonly found in SSH log entries.
        if (logEntry.contains("Accepted")) {
            return EventType.SSH_LOGIN_SUCCESS;
        } 
        
        // Check if the log entry contains "Failed" or "Invalid user", if so return EventType.SSH_LOGIN_FAILURE. This allows for identifying failed SSH login attempts based on specific keywords that are commonly found in SSH log entries.
        else if (logEntry.contains("Failed") || logEntry.contains("Invalid user")) {
            return EventType.SSH_LOGIN_FAILURE;
        } 

        // If the log entry does not contain "Accepted", "Failed", or "Invalid user", throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file.
        else {
            throw new IllegalArgumentException("Unrecognised log entry: " + logEntry);
        }
    }

    // Method to extract the source IP address from a log entry, this will be called from the parseLogFile method in the LogParser class. This is justified as it allows for separating analysis logic from validation logic.
    private String extractSourceIp(String logEntry) {

        // Check if the log entry is null or blank, if so throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file.
        if (logEntry == null || logEntry.isBlank()) {
            throw new IllegalArgumentException("Log entry cannot be null or blank");
        } 

        // Get the position of the "from" and "port" keywords in the log entry, if either is not found throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file.
        int fromPosition = logEntry.indexOf("from");
        int portPosition = logEntry.indexOf("port");
        if (fromPosition == -1 || portPosition == -1) {
           throw new IllegalArgumentException("Could not locate source IP");
        }

        if (!(portPosition -1 > fromPosition +5)) {
            throw new IllegalArgumentException("Could not locate source IP");
        }
        else {
            // Extract the source IP address from the log entry using the positions of the "from" and "port" keywords, if the extracted source IP is blank throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file. The source IP is extracted by taking the substring of the log entry starting from the position of the "from" keyword plus 5 (to skip the "from " part) and ending at the position of the "port" keyword minus 1 (to exclude the space before "port"). This ensures that only the source IP address is extracted from the log entry.
            String sourceIp = logEntry.substring(fromPosition + 5, portPosition - 1);
            if (sourceIp.isBlank()) {
                throw new IllegalArgumentException("Could not locate source IP");
            }
            String[] octets = sourceIp.split("\\.");
            if (octets.length != 4) {
                throw new IllegalArgumentException ("Invalid IP address");
            }
            for (int i=0; i< octets.length; i++) {
                if (octets[i] == null || octets[i].isBlank()) {
                    throw new IllegalArgumentException("Invalid IP address");
                }
                try {
                    int octet = Integer.parseInt(octets[i]);
                    if (octet < 0 || octet > 255) {
                        throw new IllegalArgumentException("Invalid IP address");
                    }
                }
                catch (NumberFormatException e)  {
                    throw new IllegalArgumentException("Invalid IP address ", e);
                }

               
            
            }

            if (sourceIp.equals("from") || sourceIp.equals("port")) {
                throw new IllegalArgumentException("Could not locate source IP");
            }
            
            // Return the extracted source IP address. This allows for returning the results of the extraction operation in a structured and organised manner, which can be useful for analysis and reporting purposes.
            return sourceIp;
        }
       
    }

    // Method to extract the date from a log entry, this will be called from the parseLogFile method in the LogParser class. This is justified as it allows for separating analysis logic from validation logic.
    private MonthDay extractDate(String logEntry) {

        // Check if the log entry is null or blank, if so throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file.
        if (logEntry == null || logEntry.isBlank()) {
            throw new IllegalArgumentException("Log entry cannot be null or blank");
        } 

        // Extract the timestamp from the log entry, if the timestamp is blank throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file. The timestamp is extracted by taking the substring of the log entry starting from index 0 and ending at index 15. This ensures that only the timestamp is extracted from the log entry.
        String timestamp = logEntry.substring(0, 15);
            if (timestamp.isBlank()) {
                throw new IllegalArgumentException("Could not locate timestamp");
            }

            // Extract the month as the first three characters of the timestamp in the format of MMM
            String month = timestamp.substring(0, 3);
            
            // Extract the day as the characters at index 4 and 5 of the timestamp in the format of dd
            String day = timestamp.substring(4, 6);

            // Create a DateTimeFormatter to parse the month and day into a MonthDay object, using the pattern "MMM-dd" and the Locale.ENGLISH to ensure that the month is parsed correctly regardless of the system's default locale. This allows for handling log entries that may be in different formats or locales, which can cause issues when trying to access the log file.
            DateTimeFormatter dateFormatter = DateTimeFormatter.ofPattern("MMM-dd", Locale.ENGLISH);
            MonthDay logDate = MonthDay.parse(month + "-" + day, DateTimeFormatter.ofPattern("MMM-dd", Locale.ENGLISH));

            // Return the extracted MonthDay object representing the date of the log entry. This allows for returning the results of the extraction operation in a structured and organised manner, which can be useful for analysis and reporting purposes.
            return logDate;

    }

    // Method to extract the time from a log entry, this will be called from the parseLogFile method in the LogParser class. This is justified as it allows for separating analysis logic from validation logic.
    private LocalTime extractTime(String logEntry) {

        // Check if the log entry is null or blank, if so throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file.
        if (logEntry == null || logEntry.isBlank()) {
            throw new IllegalArgumentException("Log entry cannot be null or blank");
        } 

        // Extract the timestamp from the log entry, if the timestamp is blank throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file. The timestamp is extracted by taking the substring of the log entry starting from index 0 and ending at index 15. This ensures that only the timestamp is extracted from the log entry.
        String timestamp = logEntry.substring(0, 15);
        if (timestamp.isBlank()) {
            throw new IllegalArgumentException("Could not locate timestamp");
        }

        // Extract the time as the characters at index 7 to 14 of the timestamp in the format of HH:mm:ss, and parse it into a LocalTime object. This allows for handling log entries that may be in different formats or locales, which can cause issues when trying to access the log file.
        String time = timestamp.substring(7, 15);
        LocalTime logTime = LocalTime.parse(time);
    
        // Return the extracted LocalTime object representing the time of the log entry. This allows for returning the results of the extraction operation in a structured and organised manner, which can be useful for analysis and reporting purposes.
        return logTime;
    }

    // Method to extract the username from a log entry, this will be called from the parseLogFile method in the LogParser class. This is justified as it allows for separating analysis logic from validation logic.
    private String extractUsername(String logEntry) {

        // Check if the log entry is null or blank, if so throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file.
        if (logEntry == null || logEntry.isBlank()) {
            throw new IllegalArgumentException("Log entry cannot be null or blank");
        }   

        // Get the position of the "from" keyword in the log entry, if it is not found throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file.
        int fromPosition = logEntry.indexOf("from");

        if (fromPosition == -1) {
            throw new IllegalArgumentException("Could not locate username");
        }


        // Get the position of the last space before the "from" keyword, if it is not found throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file.
        int usernameEnd = logEntry.lastIndexOf(" ", fromPosition - 1);

        if (usernameEnd == -1) {
            throw new IllegalArgumentException("Could not locate username");
        }

        // Get the position of the last space before the username, if it is not found or if it is equal to or greater than the position of the last space before the "from" keyword throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file.
        int usernameStart = logEntry.lastIndexOf(" ", usernameEnd - 1);

        if (usernameStart == -1 || usernameStart + 1 >= usernameEnd) {
            throw new IllegalArgumentException("Could not extract username");
        }

        // Extract the username from the log entry using the positions of the last space before the username and the last space before the "from" keyword, and return it. The username is extracted by taking the substring of the log entry starting from the position of the last space before the username plus 1 (to skip the space) and ending at the position of the last space before the "from" keyword. This ensures that only the username is extracted from the log entry.
        String username = logEntry.substring(usernameStart + 1, usernameEnd);
        if (username.isBlank()) {
            throw new IllegalArgumentException("Could not locate username");
        }

        if (username.equals("for")) {
            throw new IllegalArgumentException("Could not locate username");
        }

        // return the extracted username. This allows for returning the results of the extraction operation in a structured and organised manner, which can be useful for analysis and reporting purposes.
        return username;
        }

    // Method to extract the authentication method from a log entry, this will be called from the parseLogFile method in the LogParser class. This is justified as it allows for separating analysis logic from validation logic.
    private String extractAuthenticationMethod(String logEntry) {

        // Check if the log entry is null or blank, if so throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file.
        if (logEntry == null || logEntry.isBlank()) {
            throw new IllegalArgumentException("Log entry cannot be null or blank");
        }

        // Get the position of the "Failed" and "Accepted" keywords in the log entry, as well as the position of the "for" keyword. If neither "Failed" nor "Accepted" is found, throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file.
        int failedPosition = logEntry.indexOf("Failed");
        int acceptedPosition = logEntry.indexOf("Accepted");
        int forPosition = logEntry.indexOf("for");
        String authenticationMethod = "";
        if (failedPosition == -1 && acceptedPosition == -1) {
            throw new IllegalArgumentException("Log entry does not contain a recognised authentication result");
        }

        if (forPosition == -1) {
            throw new IllegalArgumentException("Could not locate username");
        }
        
        if (!(forPosition-1 > failedPosition+7)) {
            throw new IllegalArgumentException("Could not locate authentication method");
        }
        // Extract the authentication method from the log entry based on whether it contains "Failed" or "Accepted", and return it. The authentication method is extracted by taking the substring of the log entry starting from the position of the "Failed" keyword plus 7 (to skip the "Failed " part) or the position of the "Accepted" keyword plus 9 (to skip the "Accepted " part) and ending at the position of the "for" keyword minus 1 (to exclude the space before "for"). This ensures that only the authentication method is extracted from the log entry.
        else if (logEntry.contains("Failed")) {
            authenticationMethod = logEntry.substring(failedPosition+7, forPosition-1);
        }

        if (!(forPosition-1 > acceptedPosition+9)) {
            throw new IllegalArgumentException("Could not locate authentication method");
        }
        else if (logEntry.contains("Accepted")) {
            authenticationMethod = logEntry.substring(acceptedPosition+9, forPosition-1);
        }

        // Check if the extracted authentication method is blank, if so throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file.
        if (authenticationMethod.isBlank()) {
            throw new IllegalArgumentException("Authentication method cannot be blank");
        }

        if (authenticationMethod.equals("for") || authenticationMethod.equals("Failed") || authenticationMethod.equals("Accepted")) {
            throw new IllegalArgumentException("Could not locate authentication method");
        }

        // Return the extracted authentication method. This allows for returning the results of the extraction operation in a structured and organised manner, which can be useful for analysis and reporting purposes.
        return authenticationMethod;
    }

    // Method to extract the source port from a log entry, this will be called from the parseLogFile method in the LogParser class. This is justified as it allows for separating analysis logic from validation logic.
    private String extractSourcePort(String logEntry) {
        
        // Check if the log entry is null or blank, if so throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file.
        if (logEntry == null || logEntry.isBlank()) {
            throw new IllegalArgumentException("Log entry cannot be null or blank");
        } 

        // Get the position of the "port" keyword in the log entry, if it is not found throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file.
        int portPosition = logEntry.indexOf("port");
        if (portPosition == -1) {
            throw new IllegalArgumentException("Could not locate source port");
        }
        // Declare a string variable to store the extracted source port, and initialise it to an empty string. This allows for storing the extracted source port in a structured and organised manner, which can be useful for analysis and reporting purposes.
        String sourcePort = "";

        // Get the start and end positions of the source port in the log entry, if either is not found or if they are equal throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file. The start position of the source port is calculated by adding 5 to the position of the "port" keyword (to skip the "port " part), and the end position is calculated by finding the index of the first space after the start position. This ensures that only the source port is extracted from the log entry.
        int portStart = portPosition+5;
        int portEnd = logEntry.indexOf(" ", portPosition+5);
        if (portStart == -1 || portEnd == -1) {
            throw new IllegalArgumentException("Could not extract source port");
        }
   
        if (!(portEnd > portStart)) {
            throw new IllegalArgumentException("Could not extract source port");
        }

        // Extract the source port from the log entry using the start and end positions, and return it. The source port is extracted by taking the substring of the log entry starting from the start position and ending at the end position. This ensures that only the source port is extracted from the log entry.
        sourcePort = logEntry.substring(portStart, portEnd);

        // Check if the extracted source port is blank, if so throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file.
        if (sourcePort.isBlank()) {
            throw new IllegalArgumentException("Source port cannot be blank");
        }

        if (sourcePort.equals("Port")) {
            throw new IllegalArgumentException("Could not locate source port");
        }
        return sourcePort;
    }

    // Method to extract the SSH protocol from a log entry, this will be called from the parseLogFile method in the LogParser class. This is justified as it allows for separating analysis logic from validation logic.
    private String extractSshProtocol(String logEntry) {

        // Check if the log entry is null or blank, if so throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file.
        if (logEntry == null || logEntry.isBlank()) {
            throw new IllegalArgumentException("Log entry cannot be null or blank");
        } 

        // Get the position of the last space in the log entry, if it is not found throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file.
        int finalSpace = logEntry.lastIndexOf(" ");
        if (finalSpace == -1) {
            throw new IllegalArgumentException("Could not extract SSH protocol");
        }

        // Extract the SSH protocol from the log entry using the position of the last space, and return it. The SSH protocol is extracted by taking the substring of the log entry starting from the position of the last space plus 1 (to skip the space) and ending at the end of the log entry. This ensures that only the SSH protocol is extracted from the log entry.
        String sshProtocol = logEntry.substring(finalSpace +1);

        // Check if the extracted SSH protocol is blank, if so throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file.
        if (sshProtocol.isBlank()) {
            throw new IllegalArgumentException("Could not extract SSH protocol");
        }

        // Return the extracted SSH protocol. This allows for returning the results of the extraction operation in a structured and organised manner, which can be useful for analysis and reporting purposes.
        return sshProtocol;
    }

    // Method to extract event details from a log entry, this will be called from the parseLogFile method in the LogParser class. This is justified as it allows for separating analysis logic from validation logic.
    private String eventDetails(String logEntry) {

        // Check if the log entry is null or blank, if so throw an IllegalArgumentException. This allows for handling log entries that may be malformed or contain invalid data, which can cause issues when trying to access the log file.
        if (logEntry == null || logEntry.isBlank()) {
            throw new IllegalArgumentException("Log entry cannot be null or blank");
        } 
        
        // Extract the authentication method, source port, and SSH protocol from the log entry, and concatenate them into a single string representing the event details. This allows for returning the results of the extraction operation in a structured and organised manner, which can be useful for analysis and reporting purposes.
        String authenticationMethod = extractAuthenticationMethod(logEntry);
        String sourcePort = extractSourcePort(logEntry);
        String sshProtocol = extractSshProtocol(logEntry);
        String eventDetails = ("Authentication method: " +authenticationMethod + ", Source port: " +sourcePort + ", SSH protocol: " +sshProtocol);

        if (eventDetails.isBlank()) {
            throw new IllegalArgumentException("Could not locate event details");
        }
        // Return the concatenated string representing the event details. This allows for returning the results of the extraction operation in a structured and organised manner, which can be useful for analysis and reporting purposes.
        return eventDetails;
    }



}