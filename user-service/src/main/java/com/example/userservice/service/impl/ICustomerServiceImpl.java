package com.example.userservice.service.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.userservice.dto.request.SignupRequestDto;
import com.example.userservice.dto.response.SignupResponseDto;
import com.example.userservice.dto.response.UserDto;
import com.example.userservice.entity.Customer;
import com.example.userservice.enums.RoleEnum;
import com.example.userservice.exceptions.CustomerNotFoundException;
import com.example.userservice.exceptions.EntityAlreadyExists;
import com.example.userservice.mapper.UserMapper;
import com.example.userservice.repository.CustomerRepository;
import com.example.userservice.service.ICustomerService;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class ICustomerServiceImpl implements ICustomerService {

    private final CustomerRepository customerRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public SignupResponseDto saveCustomer(SignupRequestDto signupRequest) {

        Logger logger = LoggerFactory.getLogger(this.getClass());
        customerRepository.findByEmail(signupRequest.getEmail()).ifPresent((customer) -> {
            throw new EntityAlreadyExists("Customer", "email", customer.getEmail());
        });
        Customer customer = Customer.builder().email(signupRequest.getEmail())
                .firstName(signupRequest.getFirstName())
                .lastName(signupRequest.getLastName())
                .pwd(passwordEncoder.encode(signupRequest.getPassword()))
                .role(RoleEnum.USER)
                .build();
        Customer savedCustomer = customerRepository.save(customer);
        logger.info("Customer with email {} saved successfully", savedCustomer.getEmail());
        return SignupResponseDto.builder()
                .email(savedCustomer.getEmail())
                .firstName(savedCustomer.getFirstName())
                .lastName(savedCustomer.getLastName())
                .build();
    }

    @Override
    public UserDto getCustomerById(Long id) {
        Customer savedCustomer = customerRepository.findById(id)
                .orElseThrow(() -> new CustomerNotFoundException(String.format("Customer with id %d not found", id)));

        return UserMapper.toUserDto(savedCustomer);
    }

}
