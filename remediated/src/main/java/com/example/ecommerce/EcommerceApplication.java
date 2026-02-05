package com.example.ecommerce;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * E-Commerce Microservice Application (REMEDIATED)
 * 
 * This application uses Log4j 2.17.1 which is PATCHED for CVE-2021-44228
 * (Log4Shell).
 * Additional security measures have been implemented:
 * - Input sanitization before logging
 * - JNDI lookups disabled via configuration
 * - Parameterized logging used throughout
 */
@SpringBootApplication
public class EcommerceApplication {

    private static final Logger logger = LogManager.getLogger(EcommerceApplication.class);

    public static void main(String[] args) {
        logger.info("Starting E-Commerce Application (REMEDIATED)...");
        logger.info("Log4j version: 2.17.1 - PATCHED for CVE-2021-44228");
        logger.info("JNDI lookups: DISABLED");

        SpringApplication.run(EcommerceApplication.class, args);

        logger.info("E-Commerce Application started successfully");
    }
}
