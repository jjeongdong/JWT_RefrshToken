package com.example.springsecurity_jwt.service;

import com.example.springsecurity_jwt.dto.RegisterRequest;
import com.example.springsecurity_jwt.dto.SignRequest;
import com.example.springsecurity_jwt.dto.SignResponse;
import com.example.springsecurity_jwt.entity.Authority;
import com.example.springsecurity_jwt.entity.Member;
import com.example.springsecurity_jwt.jwt.JwtProvider;
import com.example.springsecurity_jwt.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class SignService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    @Transactional
    public SignResponse login(SignRequest request) {
        Member member = memberRepository.findByUsername(request.getUsername()).orElseThrow(() ->
                new BadCredentialsException("잘못된 계정정보입니다."));

        if (!passwordEncoder.matches(request.getPassword(), member.getPassword())) {
            throw new BadCredentialsException("잘못된 계정정보입니다.");
        }

        return SignResponse.builder()
                .id(member.getId())
                .username(member.getUsername())
                .roles(member.getRoles())
                .token(jwtProvider.createToken(member.getUsername(), member.getRoles()))
                .build();

    }

    @Transactional
    public boolean register(RegisterRequest request) throws Exception {
        try {
            Member member = Member.builder()
                    .username(request.getUsername())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .build();

            member.setRoles(Collections.singletonList(Authority.builder().name("ROLE_USER").build()));

            memberRepository.save(member);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            throw  new Exception("잘못된 요청입니다.");
        }
        return true;
    }

    @Transactional(readOnly = true)
    public SignResponse getMember(String username) throws Exception {
        Member member = memberRepository.findByUsername(username)
                .orElseThrow(() -> new Exception("계정을 찾을 수 없습니다."));
        return new SignResponse(member);
    }

}
