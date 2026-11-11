package com.example.loganalyser.config;

public class DetectionConfig {
 
    private final int ipFailureThreshold;
    private final int timeFailureThreshold;

    

   public DetectionConfig (int ipFailureThreshold, int timeFailureThreshold) {

    if (ipFailureThreshold <= 0 || timeFailureThreshold <= 0) {
        throw new IllegalArgumentException ("Threshold must be greater than 0");
    } 

    this.ipFailureThreshold = ipFailureThreshold;
    this.timeFailureThreshold = timeFailureThreshold;
   }

   public int getIpFailureThreshold () {
    return ipFailureThreshold;
   }

   public int getTimeFailureThreshold () {
    return timeFailureThreshold;
   }


}
