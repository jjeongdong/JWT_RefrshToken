package com.example.springsecurity_jwt.dto;

import com.example.springsecurity_jwt.entity.Authority;
import com.example.springsecurity_jwt.entity.Member;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class SignResponse {

    private Long id;

    private String username;

    private List<Authority> roles = new ArrayList<>();

    private String token;

    public SignResponse(Member member) {
        this.id = member.getId();
        this.username = member.getUsername();
        this.roles = member.getRoles();
    }
}
