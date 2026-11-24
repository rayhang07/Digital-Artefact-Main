package com.example.loganalyser.cli;
import com.example.loganalyser.model.ParseResult;
public class CommandSummary {
    private int totalLogEntries = 0;
    private int totalMalformedEntries = 0;
    private int totalUnrecognisedEntries = 0;
    private int totalOtherSSHEntries = 0;
    private ParseResult parseResult;
    private int totalAlerts;

    private final CommandAlerts commandAlerts;

    public CommandSummary (CommandAlerts commandAlerts) {
        this.commandAlerts = commandAlerts;
    }

    public void handleSummary() {
        displaySummary();
    }

    public void updateSummary(ParseResult parseResult) {
        totalLogEntries += parseResult.getLogEntries().size();
        totalMalformedEntries += parseResult.getMalformedEntries().size();
        totalUnrecognisedEntries += parseResult.getUnrecognisedEntries().size();
        totalOtherSSHEntries += parseResult.getOtherSSHEntries().size();
    }

    private void displaySummary() {

        System.out.println("\n============================================================");
        System.out.println("                    ANALYSIS SUMMARY");
        System.out.println("============================================================");
        System.out.println();
        System.out.println("  TOTAL LOG ENTRIES       : " + totalLogEntries);
        System.out.println("  MALFORMED ENTRIES       : " + totalMalformedEntries);
        System.out.println("  UNRECOGNISED ENTRIES    : " + totalUnrecognisedEntries);
        System.out.println("  OTHER SSH ENTRIES       : " + totalOtherSSHEntries);
        System.out.println("  TOTAL ALERTS            : " + commandAlerts.getAlerts().size());
        System.out.println();
        System.out.println("============================================================");
    }



}     
