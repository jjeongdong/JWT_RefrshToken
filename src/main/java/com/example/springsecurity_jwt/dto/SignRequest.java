package com.example.springsecurity_jwt.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignRequest {

    private String username;

    private String password;
}
