package com.example.userservice.exceptionhandlers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import com.example.userservice.dto.response.ErrorResponse;
import com.example.userservice.exceptions.CustomerNotFoundException;
import com.example.userservice.exceptions.EntityAlreadyExists;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(CustomerNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleCustomerNotFoundException(CustomerNotFoundException ex) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .timestamp(java.time.LocalDateTime.now())
                .message(ex.getMessage())
                .build();
        return ResponseEntity.status(404).body(errorResponse);
    }

    @ExceptionHandler(EntityAlreadyExists.class)
    public ResponseEntity<ErrorResponse> handleEntityAlreadyExists(EntityAlreadyExists ex) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .timestamp(java.time.LocalDateTime.now())
                .message(ex.getMessage())
                .build();
        return ResponseEntity.status(500).body(errorResponse);
    }

}
