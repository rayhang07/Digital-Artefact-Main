package com.example.loganalyser.cli;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.time.LocalTime;
import java.time.MonthDay;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.example.loganalyser.model.EventType;
import com.example.loganalyser.model.LogEntry;
import com.example.loganalyser.model.ParseResult;

// Unit tests for CommandSummary, covering summary updates, log entry categorisation, alert totals and summary output.
// Tests the summary calculations and displayed results using populated and empty ParseResult objects.
public class CommandSummaryTest {

    private CommandAlerts commandAlerts;
    private CommandSummary commandSummary;
    private ParseResult parseResult;
    private ByteArrayOutputStream outputStream;
    private PrintStream originalOutput;
    private final String eventDetails = ("Authentication method: password\n" + "Source port: 22\n" + "SSH protocol: ssh2");

    @BeforeEach
    public void setUp() {
        commandAlerts = new CommandAlerts();
        commandSummary = new CommandSummary(commandAlerts);

        outputStream = new ByteArrayOutputStream();
        originalOutput = System.out;
        System.setOut(new PrintStream(outputStream));
    }

    @AfterEach
    public void tearDown() {
        System.setOut(originalOutput);
    }

    // Unit test – Functional and state coverage: verifies that summary totals correctly reflect recognised, malformed, unrecognised and other SSH entries.
    @Test
    public void testUpdateSummaryWithEntries() {

        List<LogEntry> logEntries = new ArrayList<>();
        List<String> malformedEntries = new ArrayList<>();
        List<String> unrecognisedEntries = new ArrayList<>();
        List<String> otherSSHEntries = new ArrayList<>();

        LogEntry recognisedEntry = new LogEntry(EventType.SSH_LOGIN_SUCCESS, "192.168.0.10", "admin", MonthDay.of(11, 26), LocalTime.of(10, 33), (eventDetails));
        String malformedEntry = "Nov 26 10:30:00 server sshd[1234]: Failed password for admin";
        String unrecognisedEntry = "Nov 26 10:31:00 server sshd[1235]: Unknown SSH event";
        String otherSSHEntry = "Nov 26 10:32:00 server sshd[1236]: Connection closed by 192.168.0.15";

        logEntries.add(recognisedEntry);
        logEntries.add(recognisedEntry);
        malformedEntries.add(malformedEntry);
        unrecognisedEntries.add(unrecognisedEntry);
        otherSSHEntries.add(otherSSHEntry);

        parseResult = new ParseResult(logEntries, malformedEntries, unrecognisedEntries, otherSSHEntries);

        commandSummary.updateSummary(parseResult);
        commandSummary.handleSummary();

        String output = outputStream.toString();

        assertTrue(output.contains("TOTAL LOG ENTRIES       : 5"));
        assertTrue(output.contains("  TOTAL RECOGNISED ENTRIES       : 2"));
        assertTrue(output.contains("MALFORMED ENTRIES       : 1"));
        assertTrue(output.contains("UNRECOGNISED ENTRIES    : 1"));
        assertTrue(output.contains("OTHER SSH ENTRIES       : 1"));
        assertTrue(output.contains("  TOTAL ALERTS            : 0"));

    }

    // Unit test – Edge-case and state coverage: verifies that an empty ParseResult produces zero counts across all summary categories.
    @Test
    public void testUpdateSummaryWithEmptyParseResult() {
        List<LogEntry> logEntries = new ArrayList<>();
        List<String> malformedEntries = new ArrayList<>();
        List<String> unrecognisedEntries = new ArrayList<>();
        List<String> otherSSHEntries = new ArrayList<>();

        parseResult = new ParseResult(logEntries, malformedEntries, unrecognisedEntries, otherSSHEntries);
        commandSummary.updateSummary(parseResult);
        commandSummary.handleSummary();

        String output = outputStream.toString();

        assertTrue(output.contains("TOTAL LOG ENTRIES       : 0"));
        assertTrue(output.contains("  TOTAL RECOGNISED ENTRIES       : 0"));
        assertTrue(output.contains("MALFORMED ENTRIES       : 0"));
        assertTrue(output.contains("UNRECOGNISED ENTRIES    : 0"));
        assertTrue(output.contains("OTHER SSH ENTRIES       : 0"));
        assertTrue(output.contains("  TOTAL ALERTS            : 0"));

    }

    // Unit test – Output coverage: verifies that the summary display includes the heading and all expected summary categories.
    @Test
    public void testHandleSummaryDisplaysSummary() {
        commandSummary.handleSummary();
        String output = outputStream.toString();

        assertTrue(output.contains("ANALYSIS SUMMARY"));
        assertTrue(output.contains("TOTAL LOG ENTRIES"));
        assertTrue(output.contains("MALFORMED ENTRIES"));
        assertTrue(output.contains("UNRECOGNISED ENTRIES"));
        assertTrue(output.contains("OTHER SSH ENTRIES"));
        assertTrue(output.contains("TOTAL ALERTS"));
    }

}
