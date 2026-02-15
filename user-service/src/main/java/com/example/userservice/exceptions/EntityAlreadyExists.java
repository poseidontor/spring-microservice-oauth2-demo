package com.example.userservice.exceptions;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EntityAlreadyExists extends RuntimeException {

    Logger logger = LoggerFactory.getLogger(this.getClass());

    public EntityAlreadyExists(String object, String field, String value) {
        super(String.format("%s with %s : %s already exists", object, field, value));
        logger.error(String.format("%s with %s : %s already exists", object, field, value));
    }
}