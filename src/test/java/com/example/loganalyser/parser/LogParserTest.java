package com.example.loganalyser.parser;
import java.nio.file.Path;

import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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


}