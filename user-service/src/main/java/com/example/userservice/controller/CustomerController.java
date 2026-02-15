package com.example.userservice.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.userservice.dto.request.SignupRequestDto;
import com.example.userservice.dto.response.SignupResponseDto;
import com.example.userservice.dto.response.UserDto;
import com.example.userservice.service.ICustomerService;

import lombok.AllArgsConstructor;

@RestController
@AllArgsConstructor
@RequestMapping("/api/v1")
public class CustomerController {

    private final ICustomerService customerService;

    @PostMapping("/signup")
    public ResponseEntity<SignupResponseDto> signup(@RequestBody SignupRequestDto signupRequest) {

        SignupResponseDto signupResponse = customerService.saveCustomer(signupRequest);
        return ResponseEntity.ok(signupResponse);

    }

    @GetMapping("/get/{id}")
    public ResponseEntity<UserDto> getCustomerById(@PathVariable Long id) {
        UserDto userDto = customerService.getCustomerById(id);
        return ResponseEntity.status(HttpStatus.OK).body(userDto);
    }
}
