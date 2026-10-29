// package declaration for the CommandHandler class, which is part of the com.example.loganalyser.cli package
package com.example.loganalyser.cli;

// import statement for the Scanner class, which is used to read user input from the command line
import java.util.Scanner;

public class CommandHandler {
    
    // ANSI escape codes for colors stored . It is justified to store as a constant over a variable because these values are fixed and do not change during the execution of the program. Using constants improves code readability and maintainability, as it clearly indicates that these values are intended to be constant and should not be modified.
    private static final String CYAN = "\u001B[36m";
    private static final String GREEN = "\u001B[32m";

    // ANSI escape code to reset the color back to default. It is justified to store as a constant over a variable because these values are fixed and do not change during the execution of the program. Using constants improves code readability and maintainability, as it clearly indicates that these values are intended to be constant and should not be modified. It is also needed to ensure that the user interface returns to the default colour displaying coloured text, preventing the entire console output from being affected by the colour formatting.
    private static final String RESET = "\u001B[0m";

    // Method to run the command line interface, this will be called from the main method in the Main class (as the entry point of the application). This is justified as the main method is the entry point of the application and is responsible for initialising and starting the command line interface. By calling the run method from the main method, we ensure that the command line interface is started when the application is executed to actually gain user input and process commands. It is also a good practice to separate the command line interface logic from the main method, as it improves code organization and maintainability.
    public void runCli() {

        // Display the welcome banner when the application starts
        displayWelcomeBanner();
        Scanner cliScanner = new Scanner(System.in);

        // Initialise an empty variable as a string to store user inputs/commands
        String command = "";

        // Loop to continuously prompt the user for commands until the "exit" command is entered. It also handles empty inputs. A do while is used over a normal while to allow it to run at least once to display the prompt and get user input before checking the condition. This is justified as it ensures that the user is prompted for input at least once, even if they enter "exit" immediately. It also allows for a more interactive user experience, as the user can see the prompt and enter commands without having to wait for a separate prompt.
        do {
            // Display the command prompt in green color, indicating that the application is ready to accept user input
            System.out.print(GREEN + "loganalyser> " + RESET);

            // Read the user input from the command line, convert it to lowercase to facilitate command handling even if the user enters it in different cases, and store it in the command variable.
            command = cliScanner.nextLine().toLowerCase();

            // Handle the user command by calling the handleCommand method, which processes the command and performs the corresponding action based on corresponding case in the switch statement. This is justified as it allows for a modular and organized approach to command handling, making it easier to add or modify commands in the future.
            handleCommand(command);
        } while (command == null || !command.equals("exit"));
        

        
        // Close the scanner to release resources and prevent resource leaks. This is justified as it is a good practice to close resources when they are no longer needed, especially for input streams like Scanner, to free up system resources and avoid potential memory leaks.
        cliScanner.close();

    }

    // Method to handle the user command by using a switch statement to determine the appropriate action based on the command entered. A switch statement is used over if else statements as commands are direct and correspond directly to cases, any unfamiliar cases can be handled via the default block. This is used to handle different commands, making it easier to add or modify commands in the future. It also improves code readability and maintainability, as each command can be handled in its own case block.
    private void handleCommand(String command) {
        switch (command) {
            case "loganalyser --help":
                //displayHelp();
                break;
            case "exit":
                System.out.println(GREEN + "Exiting the application..." + RESET);
                break;
            case "loganalyser --analyse":
                //handleAnalysis();
                break;
            case "loganalyser --report":
                //handleReport();
                break;
            case "loganalyser --config":
                //handleConfig();
                break;
            case "loganalyser --version":
                //displayVersion();
                break; 
            case "loganalyser --alerts":
                //handleAlerts();
                break;
            case "loganalyser --summary":
                //handleSummary();
                break;
            default:
                System.out.println("Invalid command. Use the command loganalyser --help to see all commands available.");
        }
    }
    private void displayWelcomeBanner() {
    System.out.println(CYAN + """
        ==============================
          SECURITY LOG ANALYSER
        ==============================
        SSH Authentication Analysis
        """ + RESET);
    System.out.println( GREEN + "Welcome to the Log Analyser Application! \n" + "Type loganalyser --help to see all commands available \n" + "Type loganalyser exit to exit the application" + RESET);
}   
}   

