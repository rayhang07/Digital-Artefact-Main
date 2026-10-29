// import necessary packages
package com.example.loganalyser.app;

// import the CommandHandler class from the cli package to handle command line interface operations
import com.example.loganalyser.cli.CommandHandler;


public class Main {
    public static void main(String[] args) {
        // Create an instance of the CommandHandler class to handle command line interface operations. This is justified as it allows for a modular and organized approach to handling user commands, making it easier to add or modify commands in the future. It also improves code readability and maintainability, as the command handling logic is separated from the main method.
       CommandHandler commandHandler = new CommandHandler();

       // Call the runCli method of the CommandHandler object to start the command line interface and handle user commands. 
       commandHandler.runCli();
    }
}