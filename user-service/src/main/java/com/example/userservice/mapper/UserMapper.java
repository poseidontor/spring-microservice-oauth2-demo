package com.example.userservice.mapper;

import com.example.userservice.dto.response.UserDto;
import com.example.userservice.entity.Customer;

public class UserMapper {

    public static UserDto toUserDto(Customer customer) {
        return UserDto.builder().id(customer.getId()).name(customer.getFirstName() + " " + customer.getLastName())
                .email(customer.getEmail()).build();
    }

}
