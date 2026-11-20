package com.example.loganalyser.reporting;


// import necessary packages for reporting
import java.awt.Color;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;

import com.example.loganalyser.model.Alert;
import com.lowagie.text.Document;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.Paragraph;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;


// Class to format alerts into a pdf correctly
public class PdfAlertFormatter {
    

    // Method to format the pdf taking the list of alerts, and the the path to the directory. Throws an IOException which is caught during generation for proper error handling
    public void formatPdf(List<Alert> alerts, Path pathToDirectory) throws IOException {


        // Checks that if the provided list of alerts is empty and will therefore throw an error to the user. This ensures that a user cannot generate a blank report and can only generate reports from security alerts
        if (alerts.isEmpty() || alerts == null ) {
            throw new IllegalStateException("Cannot generate a report because no alerts were detected.");
        } 

        // Instantiate a new document object 
        Document document = new Document();

        // Declare the initial base report name  
        String fileName = "SecurityReport-" + LocalDate.now() + ".pdf";

        // A counter to is used to ensure we do not create files that have the exact same name as this causes them to become overriden
        int counter = 0;

        // Declare the path to the report file and the outputstream
        FileOutputStream outputStream;
        Path reportFilePath = pathToDirectory.resolve(fileName);

        // Run while the current file path exists 
        while (Files.exists(reportFilePath)) {

        // increment the counter to append to the file name
        counter ++;

        // Update the filename to include the counter so a new file can be created instead of overriding current data 
        fileName = "SecurityReport-" + LocalDate.now() + "-(" + counter + ").pdf"; 

        // Combines path to the directory with the filename and stores it in a new path object
        reportFilePath = pathToDirectory.resolve(fileName);

        }

        // Instantiate a new FileOutputstream object so that java can write data to file. Also convert the path to the report into a file object
        outputStream = new FileOutputStream(reportFilePath.toFile()); 

        // Creates and returns a PdfWriter taking the document and the outputStream as args 
        PdfWriter.getInstance(document, outputStream);

        // Open the document to be written to
        document.open();


        // Create and set fonts for different 
        Font bannerFont = new Font(Font.HELVETICA, 18, Font.BOLD, Color.WHITE);
        Font headingFont = new Font(Font.HELVETICA, 13, Font.BOLD, Color.BLACK);
        Font bodyFont = new Font(Font.HELVETICA, 10, Font.NORMAL, Color.BLACK);
        Font titleFont = new Font(Font.HELVETICA, 22, Font.BOLD, Color.RED);

        // Create a title paragraph containing the title and date of report as a string in the title font
        Paragraph title = new Paragraph("SECURITY ANALYSIS REPORT " + LocalDate.now().toString(), titleFont);

        // Align the title in the centre of the pdf
        title.setAlignment(Element.ALIGN_CENTER);

        // Add spacing under the title for a clean and readable format
        title.setSpacingAfter(10);

        // add the title to the document
        document.add(title);
               
            // Loop through each alert inside of the list of alerts
            for (Alert alert: alerts) {

            // Create a banner for security alert using a table
            PdfPTable alertBanner = new PdfPTable(1);

            // Ensure its width takes up the full width of the page
            alertBanner.setWidthPercentage(100);

            // Align it centrally
            alertBanner.setHorizontalAlignment(Element.ALIGN_CENTER);

            // Create a title for the banner to display each security alert
            Paragraph alertTitle = new Paragraph("SECURITY ALERT", bannerFont);

            // align it centrally
            alertTitle.setAlignment(Element.ALIGN_CENTER);

            // create a cell to house the title
            PdfPCell alertBannerCell = new PdfPCell(alertTitle);

            // set the background colour as dark red for a clean professional aesthetic
            alertBannerCell.setBackgroundColor(new Color(160, 30, 30));

            // remove the border
            alertBannerCell.setBorder(0);

            // add padding to the sides of the border 
            alertBannerCell.setPadding(10);

            // add spacing before each alert to ensure elements such as the title do not collide with the banner
            alertBanner.setSpacingBefore(20);

            // align the cell (title) centrally
            alertBannerCell.setHorizontalAlignment(Element.ALIGN_CENTER);

            // add the cell to the alert banner
            alertBanner.addCell(alertBannerCell);

            // add the banner to the document
            document.add(alertBanner);


            // Rule information

            // create a paragraph for the rule using the heading font
            Paragraph ruleHeading = new Paragraph("Rule Information", headingFont);

            // add spacing before and after to avoid colliding with other elements in the pdf
            ruleHeading.setSpacingBefore(15);
            ruleHeading.setSpacingAfter(5);

            // add the heading to the document
            document.add(ruleHeading);

            // add both the rule that was triggered and its description to the document using the getters, specifying font
            document.add(new Paragraph("Rule: " + alert.getRuleName(), bodyFont));
            document.add(new Paragraph("Description: " + alert.getRuleDescription(), bodyFont));

            // create a paragraph for the source details using the headingfont
            Paragraph sourceHeading = new Paragraph("Source Details", headingFont);

            // add spacing before and after to avoid colliding with other elements in the pdf
            sourceHeading.setSpacingBefore(15);
            sourceHeading.setSpacingAfter(5);

            // add the heading to the document
            document.add(sourceHeading);

            // add the source details including ip and username to the document using the getters, specifying font
            document.add(new Paragraph("Source IP: " + alert.getSourceIp(), bodyFont));
            document.add(new Paragraph("Username: " + alert.getUsername(), bodyFont));

            // Create a paragraph for the event details using the heading font
            Paragraph eventHeading = new Paragraph("Event Details", headingFont);

            // set spacing before and after so that it doesnt collide with other elements on the document
            eventHeading.setSpacingBefore(15);
            eventHeading.setSpacingAfter(5);

            // add the heading to the document
            document.add(eventHeading);

            // add the event details including failed attempts, timestamp, and event details 
            document.add(new Paragraph("Failed Attempts: " + alert.getFailedAttemptCount(), bodyFont));
            document.add(new Paragraph("Date: " + alert.getDate(), bodyFont));
            document.add(new Paragraph("Time: " + alert.getTime(), bodyFont));
            document.add(new Paragraph(alert.getEventDetails(), bodyFont));


        }

        // close the document, this ensures safe document handling meaning the document is cleanly closed and cannot be altered any more. This ensures that the user cannot alter fields in the pdf directly.
        document.close();
       
    }
}
