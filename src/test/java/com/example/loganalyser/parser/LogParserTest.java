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

    @Test 
    public void testParseLogFileWithValidSshLogEntry() throws Exception {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/sample.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getUnrecognisedEntries().isEmpty());
        assertFalse(parseResult.getOtherSSHEntries().isEmpty());
    }

    @Test
    public void testParseLogFileWithEmptyLogFile() throws Exception {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/empty.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getUnrecognisedEntries().isEmpty());
        assertTrue(parseResult.getOtherSSHEntries().isEmpty());
    }

    @Test
    public void testParseLogFileWithMalformedLogFile() throws Exception {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/malformed.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getUnrecognisedEntries().isEmpty());
        assertTrue(parseResult.getOtherSSHEntries().isEmpty());

    }

    @Test 
    public void testParseLogFileWithUnrecognisedLogFile() throws Exception {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/unrecognised.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertFalse(parseResult.getUnrecognisedEntries().isEmpty());
        assertTrue(parseResult.getOtherSSHEntries().isEmpty());
    }

    @Test 
    public void testParseLogFileWithOtherSSHLogFile() throws Exception {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/other_ssh.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getUnrecognisedEntries().isEmpty());
        assertFalse(parseResult.getOtherSSHEntries().isEmpty());
    }

    @Test 
    public void testParseLogFileWithMixedLogFile() throws Exception {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/mixed.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertFalse(parseResult.getUnrecognisedEntries().isEmpty());
        assertFalse(parseResult.getOtherSSHEntries().isEmpty());

        
    }

    @Test
    public void testParseLogFileWithValidIpv4Address() throws Exception {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_ip.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getSourceIp().equals("192.168.1.10")));

    
    }

    @Test
    public void testParseLogFileWithLowerBoundaryIpv4Address() throws Exception {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_ip.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getSourceIp().equals("0.0.0.0")));

    
    }

    @Test
    public void testParseLogFileWithUpperBoundaryIpv4Address() throws Exception {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_ip.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getSourceIp().equals("255.255.255.255")));
 
    
    }

    @Test
    public void testParseLogFileWithTooFewOctetsIpv4Address() throws IOException {    
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ip.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("192.168.1 port")));
    }

    @Test
    public void testParseLogFileWithTooManyOctetsIpv4Address() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ip.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("192.168.1.10.5")));
    }

    @Test
    public void testParseLogFileWithNonNumericIpv4Address() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ip.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty()); 
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("192.168.a.10")));
    }

    @Test
    public void testParseLogFileWithOctetAbove255Ipv4Address() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ip.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("192.168.1.256")));
    }

    @Test
    public void testParseLogFileWithNegativeOctectIpv4Address() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ip.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("192.168.-1.10")));
    }

    @Test
    public void testParseLogFileWithEmptyOctectIpv4Address() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ip.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty()); 
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("192.168..10")));
    }

    @Test
    public void testParseLogFileWithMissingIpv4Address() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ip.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty()); 
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("Failed password for alice")));
    }

    @Test
    public void testParseLogFileWithValidDate() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_date.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getDate().equals(MonthDay.of(11, 9))));
    }

    @Test
    public void testParseLogFileWithLeapYearDate() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_date.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getDate().equals(MonthDay.of(2, 29))));
    }
    
    @Test
    public void testParseLogFileWithInvalidDate() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_date.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("Feb 30")));
    }

    @Test
    public void testParseLogFileWithMissingDate() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_date.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("12:00:00")));
    }

    @Test
    public void testParseLogFileWithValidTime() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_time.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getTime().equals(LocalTime.of(12, 30, 45))));
    }
    @Test
    public void testParseLogFileWithMidnightTime() throws IOException {  
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_time.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getTime().equals(LocalTime.MIDNIGHT)));
    }

    @Test
    public void testParseLogFileWithEndOfDayTime() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_time.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getTime().equals(LocalTime.of(23, 59, 59))));
    }

    @Test
    public void testParseLogFileWithHourAbove23() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_time.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("25:00:00")));
    }

    @Test
    public void testParseLogFileWithMinuteAbove59() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_time.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("12:60:00")));
    }

    @Test
    public void testParseLogFileWithSecondAbove59() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_time.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("12:30:60")));
    }   

    @Test
    public void testParseLogFileWithMissingTime() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_time.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("Nov 09")));
    }

    @Test
    public void testParseLogFileWithValidUsername() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_username.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getUsername().equals("alice")));
    }
    @Test
    public void testParseLogFileWithAlphanumericUsername() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_username.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getUsername().equals("bob123")));
    }    
    @Test
    public void testParseLogFileWithRootUsername() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_username.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getUsername().equals("root")));
    }

    @Test
    public void testParseLogFileWithMissingUsername() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_username.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("Failed password for from")));
    }

    @Test
    public void testParseLogFileWithEmptyUsername() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_username.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("Failed password for  from")));
    }

    // Tests that the parser correctly extracts valid authentication methods.

    @Test
    public void testParseLogFileWithValidPasswordAuthenticationMethod() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_authentication_method.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getEventDetails().contains("password")));
    }

    @Test
    public void testParseLogFileWithValidPublicKeyAuthenticationMethod() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_authentication_method.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getEventDetails().contains("publickey")));
    }

    @Test
    public void testParseLogFileWithValidKeyboardInteractiveAuthenticationMethod() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_authentication_method.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getEventDetails().contains("keyboard-interactive")));
    }

    @Test
    public void testParseLogFileWithMissingAuthenticationMethod() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_authentication_method.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("Failed for alice")));
    }

    @Test
    public void testParseLogFileWithMissingForKeyword() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_authentication_method.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("Failed password alice")));
    }

    @Test
    public void testParseLogFileWithMissingAuthenticationResult() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_authentication_method.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("for alice")));
    }
    // Tests that the parser rejects SSH log entries with invalid authentication methods.

    @Test
    public void testParseLogFileWithBlankAuthenticationMethod() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_authentication_method.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("Failed  for alice")));
    }
    // Tests that the parser correctly extracts valid source ports.

    @Test
    public void testParseLogFileWithValidSourcePort() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_source_port.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getEventDetails().contains("54321")));
    }

    @Test
    public void testParseLogFileWithLowerBoundSourcePort() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_source_port.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getEventDetails().contains("0")));
    }

    @Test
    public void testParseLogFileWithUpperBoundSourcePort() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_source_port.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().anyMatch(entry -> entry.getEventDetails().contains("65535")));
    }

    // Tests that the parser rejects SSH log entries containing invalid source ports.

    @Test
    public void testParseLogFileWithNegativeSourcePort() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_source_port.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("port -1")));
    }

    @Test
    public void testParseLogFileWithSourcePortAboveMaximum() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_source_port.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("port 65536")));
    }

    @Test
    public void testParseLogFileWithNonNumericSourcePort() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_source_port.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("port abc")));
    }

    @Test
    public void testParseLogFileWithAlphanumericSourcePort() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_source_port.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("port 22abc")));
    }

    @Test
    public void testParseLogFileWithDecimalSourcePort() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_source_port.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("port 12.5")));
    }

    @Test
    public void testParseLogFileWithMissingSourcePort() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_source_port.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("192.168.1.50 ssh2")));
    }

    @Test
    public void testParseLogFileWithEmptySourcePort() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_source_port.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("port  ssh2")));
    }
// Tests that the parser correctly extracts the SSH protocol from valid log entries.

    @Test
    public void testParseLogFileWithSsh2Protocol() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_ssh_protocol.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().allMatch(entry -> entry.getEventDetails().contains("ssh2")));
    }

    // Tests that the parser rejects SSH log entries with unsupported or missing protocols.

    @Test
    public void testParseLogFileWithSsh1Protocol() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ssh_protocol.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("ssh1")));
    }

    @Test
    public void testParseLogFileWithSsh3Protocol() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ssh_protocol.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("ssh3")));
    }

    @Test
    public void testParseLogFileWithUnrecognisedSshProtocol() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ssh_protocol.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("invalid")));
    }

    @Test
    public void testParseLogFileWithMissingSshProtocol() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ssh_protocol.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("port 54324")));
    }

    @Test
    public void testParseLogFileWithEmptySshProtocol() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_ssh_protocol.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().stream().anyMatch(line -> line.contains("port 54325 ")));
    }

// Tests that the parser correctly identifies successful and failed SSH login events.

    @Test
    public void testParseLogFileWithSuccessfulLoginEvent() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_event_type.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().filter(entry -> entry.getEventType() == EventType.SSH_LOGIN_SUCCESS).count() == 2);
    }

    @Test
    public void testParseLogFileWithFailedLoginEvent() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/valid_event_type.log");
        parseResult = logParser.parseLogFile(path);
        assertFalse(parseResult.getLogEntries().isEmpty());
        assertTrue(parseResult.getMalformedEntries().isEmpty());
        assertTrue(parseResult.getLogEntries().stream().filter(entry -> entry.getEventType() == EventType.SSH_LOGIN_FAILURE).count() == 3);
    }
    // Tests that the parser rejects SSH log entries with unrecognised event types.

    @Test
    public void testParseLogFileWithUnrecognisedEventType() throws IOException {
        Path path = Path.of("src/test/java/com/example/loganalyser/resources/logs/invalid_event_type.log");
        parseResult = logParser.parseLogFile(path);
        assertTrue(parseResult.getLogEntries().isEmpty());
        assertEquals(4, parseResult.getOtherSSHEntries().size());
        assertFalse(parseResult.getMalformedEntries().isEmpty());
    }
}