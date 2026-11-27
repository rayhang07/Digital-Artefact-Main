package com.example.loganalyser.parser;

import java.io.IOException;
import java.nio.file.Path;
import java.time.LocalTime;
import java.time.MonthDay;

import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.example.loganalyser.model.EventType;
import com.example.loganalyser.model.ParseResult;

// Unit tests for LogParser, covering log classification, valid and malformed entries, and extraction of SSH log fields.
// Tests parsing behaviour using sample log files containing valid, invalid, boundary and mixed SSH log entries.
public class LogParserTest {

    private LogParser logParser;
    private ParseResult parseResult;

    @BeforeEach
    public void setUp() {
        logParser = new LogParser();
    }

    @AfterEach
    public void tearDown() {
        logParser = null;
    }

    // Unit test – Functional coverage: verifies that a valid SSH log file is parsed into recognised entries and other SSH entries without malformed or unrecognised entries.
    @Test
    public void testParseLogFileWithValidSshLogEntry() throws Exception {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/sample.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getUnrecognisedEntries().isEmpty());
        assertFalse(parseResult.getOtherSSHEntries().isEmpty());
    }

    // Unit test – Edge-case coverage: verifies that parsing an empty log file produces no recognised, malformed, unrecognised or other SSH entries.
    @Test
    public void testParseLogFileWithEmptyLogFile() throws Exception {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/empty.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getUnrecognisedEntries().isEmpty());
        assertTrue(parseResult.getOtherSSHEntries().isEmpty());
    }

    // Unit test – Error-handling coverage: verifies that malformed log entries are classified as malformed rather than recognised or unrecognised.
    @Test
    public void testParseLogFileWithMalformedLogFile() throws Exception {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/malformed.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getUnrecognisedEntries().isEmpty());
        assertTrue(parseResult.getOtherSSHEntries().isEmpty());

    }

    // Unit test – Classification coverage: verifies that unrecognised log entries are placed in the unrecognised entries collection.
    @Test
    public void testParseLogFileWithUnrecognisedLogFile() throws Exception {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/unrecognised.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertFalse(parseResult.getUnrecognisedEntries().isEmpty());
        assertTrue(parseResult.getOtherSSHEntries().isEmpty());
    }

    // Unit test – Classification coverage: verifies that SSH entries outside the recognised authentication event types are classified as other SSH entries.
    @Test
    public void testParseLogFileWithOtherSSHLogFile() throws Exception {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/other_ssh.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getUnrecognisedEntries().isEmpty());
        assertFalse(parseResult.getOtherSSHEntries().isEmpty());
    }

    // Unit test – Mixed-input coverage: verifies that a file containing different entry types is separated into the appropriate parser result collections.
    @Test
    public void testParseLogFileWithMixedLogFile() throws Exception {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/mixed.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertFalse(parseResult.getUnrecognisedEntries().isEmpty());
        assertFalse(parseResult.getOtherSSHEntries().isEmpty());

    }

    // Unit test – Valid-input coverage: verifies that a valid IPv4 address is extracted from a parsed SSH log entry.
    @Test
    public void testParseLogFileWithValidIpv4Address() throws Exception {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_ip.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getSourceIp().equals("192.168.1.10")));

    }

    // Unit test – Lower-boundary coverage: verifies that the lowest valid IPv4 address, 0.0.0.0, is accepted.
    @Test
    public void testParseLogFileWithLowerBoundaryIpv4Address() throws Exception {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_ip.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getSourceIp().equals("0.0.0.0")));

    }

    // Unit test – Upper-boundary coverage: verifies that the highest valid IPv4 address, 255.255.255.255, is accepted.
    @Test
    public void testParseLogFileWithUpperBoundaryIpv4Address() throws Exception {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_ip.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getSourceIp().equals("255.255.255.255")));

    }

    // Unit test – Invalid-input coverage: verifies that an IPv4 address with too few octets is rejected and recorded as malformed.
    @Test
    public void testParseLogFileWithTooFewOctetsIpv4Address() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ip.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("192.168.1 port")));
    }

    // Unit test – Invalid-input coverage: verifies that an IPv4 address with too many octets is rejected and recorded as malformed.
    @Test
    public void testParseLogFileWithTooManyOctetsIpv4Address() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ip.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("192.168.1.10.5")));
    }

    // Unit test – Invalid-input coverage: verifies that an IPv4 address containing non-numeric octets is rejected and recorded as malformed.
    @Test
    public void testParseLogFileWithNonNumericIpv4Address() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ip.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("192.168.a.10")));
    }

    // Unit test – Upper-boundary validation: verifies that an IPv4 address containing an octet above 255 is rejected.
    @Test
    public void testParseLogFileWithOctetAbove255Ipv4Address() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ip.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("192.168.1.256")));
    }

    // Unit test – Invalid-input coverage: verifies that an IPv4 address containing a negative octet is rejected.
    @Test
    public void testParseLogFileWithNegativeOctectIpv4Address() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ip.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("192.168.-1.10")));
    }

    // Unit test – Invalid-input coverage: verifies that an IPv4 address containing an empty octet is rejected.
    @Test
    public void testParseLogFileWithEmptyOctectIpv4Address() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ip.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("192.168..10")));
    }

    // Unit test – Missing-field validation: verifies that an SSH log entry without an IPv4 address is rejected as malformed.
    @Test
    public void testParseLogFileWithMissingIpv4Address() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ip.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("Failed password for alice")));
    }

    // Unit test – Valid-input coverage: verifies that a valid date is extracted from a parsed SSH log entry.
    @Test
    public void testParseLogFileWithValidDate() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_date.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getDate().equals(MonthDay.of(11, 9))));
    }

    // Unit test – Boundary coverage: verifies that February 29 is accepted as a valid leap-year date.
    @Test
    public void testParseLogFileWithLeapYearDate() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_date.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getDate().equals(MonthDay.of(2, 29))));
    }

    // Unit test – Invalid-input coverage: verifies that an impossible calendar date, February 30, is rejected as malformed.
    @Test
    public void testParseLogFileWithInvalidDate() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_date.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("Feb 30")));
    }

    // Unit test – Missing-field validation: verifies that an SSH log entry without a date is rejected as malformed.
    @Test
    public void testParseLogFileWithMissingDate() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_date.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("12:00:00")));
    }

    // Unit test – Valid-input coverage: verifies that a valid time is extracted from a parsed SSH log entry.
    @Test
    public void testParseLogFileWithValidTime() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_time.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getTime().equals(LocalTime.of(12, 30, 45))));
    }

    // Unit test – Lower-boundary coverage: verifies that midnight, 00:00:00, is accepted as a valid time.
    @Test
    public void testParseLogFileWithMidnightTime() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_time.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getTime().equals(LocalTime.MIDNIGHT)));
    }

    // Unit test – Upper-boundary coverage: verifies that the final second of the day, 23:59:59, is accepted as a valid time.
    @Test
    public void testParseLogFileWithEndOfDayTime() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_time.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getTime().equals(LocalTime.of(23, 59, 59))));
    }

    // Unit test – Upper-boundary validation: verifies that an hour above 23 is rejected and recorded as malformed.
    @Test
    public void testParseLogFileWithHourAbove23() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_time.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("25:00:00")));
    }

    // Unit test – Upper-boundary validation: verifies that a minute above 59 is rejected and recorded as malformed.
    @Test
    public void testParseLogFileWithMinuteAbove59() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_time.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("12:60:00")));
    }

    // Unit test – Upper-boundary validation: verifies that a second above 59 is rejected and recorded as malformed.
    @Test
    public void testParseLogFileWithSecondAbove59() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_time.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("12:30:60")));
    }

    // Unit test – Missing-field validation: verifies that an SSH log entry without a time is rejected as malformed.
    @Test
    public void testParseLogFileWithMissingTime() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_time.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("Nov 09")));
    }

    // Unit test – Valid-input coverage: verifies that a valid username is extracted from a parsed SSH log entry.
    @Test
    public void testParseLogFileWithValidUsername() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_username.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getUsername().equals("alice")));
    }

    // Unit test – Valid-input coverage: verifies that a username containing letters and numbers is accepted.
    @Test
    public void testParseLogFileWithAlphanumericUsername() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_username.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getUsername().equals("bob123")));
    }

    // Unit test – Valid-input coverage: verifies that the root username is accepted and extracted correctly.
    @Test
    public void testParseLogFileWithRootUsername() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_username.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getUsername().equals("root")));
    }

    // Unit test – Missing-field validation: verifies that an SSH log entry without a username is rejected as malformed.
    @Test
    public void testParseLogFileWithMissingUsername() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_username.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("Failed password for from")));
    }

    // Unit test – Invalid-input coverage: verifies that an SSH log entry with an empty username is rejected as malformed.
    @Test
    public void testParseLogFileWithEmptyUsername() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_username.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("Failed password for  from")));
    }

    // Unit test – Valid-input coverage: verifies that password is recognised as a valid authentication method.
    @Test
    public void testParseLogFileWithValidPasswordAuthenticationMethod() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_authentication_method.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getEventDetails().contains("password")));
    }

    // Unit test – Valid-input coverage: verifies that publickey is recognised as a valid authentication method.
    @Test
    public void testParseLogFileWithValidPublicKeyAuthenticationMethod() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_authentication_method.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getEventDetails().contains("publickey")));
    }

    // Unit test – Valid-input coverage: verifies that keyboard-interactive is recognised as a valid authentication method.
    @Test
    public void testParseLogFileWithValidKeyboardInteractiveAuthenticationMethod() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_authentication_method.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getEventDetails().contains("keyboard-interactive")));
    }

    // Unit test – Missing-field validation: verifies that an SSH log entry without an authentication method is rejected as malformed.
    @Test
    public void testParseLogFileWithMissingAuthenticationMethod() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_authentication_method.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("Failed for alice")));
    }

    // Unit test – Format validation: verifies that an SSH log entry missing the required "for" keyword is rejected as malformed.
    @Test
    public void testParseLogFileWithMissingForKeyword() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_authentication_method.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("Failed password alice")));
    }

    // Unit test – Missing-field validation: verifies that an SSH log entry without an authentication result is rejected as malformed.
    @Test
    public void testParseLogFileWithMissingAuthenticationResult() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_authentication_method.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("for alice")));
    }

    // Unit test – Invalid-input coverage: verifies that an SSH log entry with a blank authentication method is rejected as malformed.
    @Test
    public void testParseLogFileWithBlankAuthenticationMethod() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_authentication_method.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("Failed  for alice")));
    }

    // Unit test – Valid-input coverage: verifies that a valid source port is extracted from a parsed SSH log entry.
    @Test
    public void testParseLogFileWithValidSourcePort() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_source_port.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getEventDetails().contains("54321")));
    }

    // Unit test – Lower-boundary coverage: verifies that source port 0 is accepted as the lowest valid port number.
    @Test
    public void testParseLogFileWithLowerBoundSourcePort() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_source_port.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getEventDetails().contains("0")));
    }

    // Unit test – Upper-boundary coverage: verifies that source port 65535 is accepted as the highest valid port number.
    @Test
    public void testParseLogFileWithUpperBoundSourcePort() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_source_port.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getEventDetails().contains("65535")));
    }

    // Unit test – Lower-boundary validation: verifies that a negative source port is rejected as malformed.
    @Test
    public void testParseLogFileWithNegativeSourcePort() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_source_port.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("port -1")));
    }

    // Unit test – Upper-boundary validation: verifies that a source port above 65535 is rejected as malformed.
    @Test
    public void testParseLogFileWithSourcePortAboveMaximum() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_source_port.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("port 65536")));
    }

    // Unit test – Invalid-input coverage: verifies that a non-numeric source port is rejected as malformed.
    @Test
    public void testParseLogFileWithNonNumericSourcePort() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_source_port.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("port abc")));
    }

    // Unit test – Invalid-input coverage: verifies that an alphanumeric source port is rejected as malformed.
    @Test
    public void testParseLogFileWithAlphanumericSourcePort() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_source_port.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("port 22abc")));
    }

    // Unit test – Invalid-input coverage: verifies that a decimal source port is rejected as malformed.
    @Test
    public void testParseLogFileWithDecimalSourcePort() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_source_port.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("port 12.5")));
    }

    // Unit test – Missing-field validation: verifies that an SSH log entry without a source port is rejected as malformed.
    @Test
    public void testParseLogFileWithMissingSourcePort() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_source_port.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("192.168.1.50 ssh2")));
    }

    // Unit test – Missing-field validation: verifies that an SSH log entry with an empty source port is rejected as malformed.
    @Test
    public void testParseLogFileWithEmptySourcePort() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_source_port.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("port  ssh2")));
    }

    // Unit test – Valid-input coverage: verifies that the SSH2 protocol is extracted from valid SSH log entries.
    @Test
    public void testParseLogFileWithSsh2Protocol() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_ssh_protocol.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().allMatch(entry -> entry.getEventDetails().contains("ssh2")));
    }

    // Unit test – Invalid-input coverage: verifies that the unsupported SSH1 protocol is rejected as malformed.
    @Test
    public void testParseLogFileWithSsh1Protocol() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ssh_protocol.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("ssh1")));
    }

    // Unit test – Invalid-input coverage: verifies that the unsupported SSH3 protocol is rejected as malformed.
    @Test
    public void testParseLogFileWithSsh3Protocol() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ssh_protocol.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("ssh3")));
    }

    // Unit test – Invalid-input coverage: verifies that an unrecognised SSH protocol value is rejected as malformed.
    @Test
    public void testParseLogFileWithUnrecognisedSshProtocol() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ssh_protocol.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("invalid")));
    }

    // Unit test – Missing-field validation: verifies that an SSH log entry without a protocol value is rejected as malformed.
    @Test
    public void testParseLogFileWithMissingSshProtocol() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ssh_protocol.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("port 54324")));
    }

    // Unit test – Missing-field validation: verifies that an SSH log entry with an empty protocol value is rejected as malformed.
    @Test
    public void testParseLogFileWithEmptySshProtocol() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ssh_protocol.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("port 54325 ")));
    }

    // Unit test – Event classification coverage: verifies that successful SSH login entries are recognised and counted correctly.
    @Test
    public void testParseLogFileWithSuccessfulLoginEvent() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_event_type.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().filter(entry -> entry.getEventType() == EventType.SSH_LOGIN_SUCCESS).count() == 2);
    }

    // Unit test – Event classification coverage: verifies that failed SSH login entries are recognised and counted correctly.
    @Test
    public void testParseLogFileWithFailedLoginEvent() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_event_type.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().filter(entry -> entry.getEventType() == EventType.SSH_LOGIN_FAILURE).count() == 3);
    }

    // Unit test – Classification and error-handling coverage: verifies that unrecognised SSH event types are placed in the other SSH collection and malformed entries are recorded.
    @Test
    public void testParseLogFileWithUnrecognisedEventType() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_event_type.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertEquals(4, parseResult.getOtherSSHEntries().size());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
    }
}
