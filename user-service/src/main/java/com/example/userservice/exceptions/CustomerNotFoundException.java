package com.example.userservice.exceptions;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CustomerNotFoundException extends RuntimeException {

    Logger logger = LoggerFactory.getLogger(this.getClass());

    public CustomerNotFoundException(String message) {
        super(message);
        logger.error(message);
    }

}
