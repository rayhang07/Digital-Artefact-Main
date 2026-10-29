package com.example.loganalyser.app;
import com.example.loganalyser.cli.CommandHandler;


public class Main {
    public static void main(String[] args) {
       CommandHandler commandHandler = new CommandHandler();
       commandHandler.runCli();
    }
}