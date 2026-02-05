package com.example.ecommerce;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * E-Commerce Microservice Application
 * 
 * WARNING: This application uses Log4j 2.14.1 which is VULNERABLE to CVE-2021-44228 (Log4Shell).
 * This version is intentionally vulnerable for demonstration purposes only.
 * DO NOT deploy this application in a production environment.
 */
@SpringBootApplication
public class EcommerceApplication {

    private static final Logger logger = LogManager.getLogger(EcommerceApplication.class);

    public static void main(String[] args) {
        logger.info("Starting E-Commerce Application...");
        logger.warn("WARNING: This application uses a VULNERABLE version of Log4j (2.14.1)");
        logger.warn("CVE-2021-44228 (Log4Shell) - CVSS Score: 10.0 CRITICAL");
        
        SpringApplication.run(EcommerceApplication.class, args);
        
        logger.info("E-Commerce Application started successfully");
    }
}
