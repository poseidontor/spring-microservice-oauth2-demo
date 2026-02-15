package com.example.userservice.dto.response;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Builder
@Getter
@Setter
public class SignupResponseDto {
    private String email;
    private String firstName;
    private String lastName;

}
