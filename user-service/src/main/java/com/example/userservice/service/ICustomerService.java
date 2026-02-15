package com.example.userservice.service;

import com.example.userservice.dto.request.SignupRequestDto;
import com.example.userservice.dto.response.SignupResponseDto;
import com.example.userservice.dto.response.UserDto;

public interface ICustomerService {
    public SignupResponseDto saveCustomer(SignupRequestDto signupRequest);

    public UserDto getCustomerById(Long id);

}
