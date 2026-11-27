package com.example.loganalyser.cli;
import com.example.loganalyser.model.ParseResult;

// This class is used to provide and keep track of cumulative statistics from the current sessions analysis 
public class CommandSummary {

    // initialise the cumulative totals and command alerts =
    private int totalLogEntries = 0;
    private int totalMalformedEntries = 0;
    private int totalUnrecognisedEntries = 0;
    private int totalOtherSSHEntries = 0;
    private final CommandAlerts commandAlerts;

    // constructor to initialise commandalerts to be able to access the current alerts stored
    public CommandSummary (CommandAlerts commandAlerts) {
        this.commandAlerts = commandAlerts;
    }

    // method to handle the summary command displaying analytics
    public void handleSummary() {
        displaySummary();
    }

    // method to update summary by adding every parsed result lists length to the total which is called after every analysis
    public void updateSummary(ParseResult parseResult) {
        totalLogEntries += parseResult.getLogEntries().size();
        totalMalformedEntries += parseResult.getMalformedEntries().size();
        totalUnrecognisedEntries += parseResult.getUnrecognisedEntries().size();
        totalOtherSSHEntries += parseResult.getOtherSSHEntries().size();
    }


    // method to present the analytics in a clean and aesthetic way for the user
    private void displaySummary() {
        System.out.println("\n============================================================");
        System.out.println("                    ANALYSIS SUMMARY");
        System.out.println("============================================================");
        System.out.println();
        System.out.println("  TOTAL LOG ENTRIES       : " + (totalLogEntries + totalMalformedEntries + totalUnrecognisedEntries + totalOtherSSHEntries));
        System.out.println("  TOTAL RECOGNISED ENTRIES       : " + totalLogEntries);
        System.out.println("  MALFORMED ENTRIES       : " + totalMalformedEntries);
        System.out.println("  UNRECOGNISED ENTRIES    : " + totalUnrecognisedEntries);
        System.out.println("  OTHER SSH ENTRIES       : " + totalOtherSSHEntries);
        System.out.println("  TOTAL ALERTS            : " + commandAlerts.getAlerts().size());
        System.out.println();
        System.out.println("============================================================");
    }

}     
