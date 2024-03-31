package com.example.springsecurity_jwt.service;

import com.example.springsecurity_jwt.util.SecurityUtil;
import com.example.springsecurity_jwt.dto.*;
import com.example.springsecurity_jwt.entity.Authority;
import com.example.springsecurity_jwt.entity.Member;
import com.example.springsecurity_jwt.jwt.JwtProvider;
import com.example.springsecurity_jwt.redis.RefreshToken;
import com.example.springsecurity_jwt.redis.RefreshTokenRepository;
import com.example.springsecurity_jwt.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class SignService {

    private final MemberRepository memberRepository;
    private final RefreshTokenRepository refreshTokenRepository;
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
                .token(TokenResponse.builder()
                        .accessToken(jwtProvider.createAccessToken(member.getUsername(), member.getRoles()))
                        .refreshToken(jwtProvider.createRefreshToken(member.getUsername()))
                        .build())
                .build();
    }

    public TokenResponse reissue(TokenRequest request) {
        RefreshToken DBrefreshToken = refreshTokenRepository.findById(request.getRefreshToken())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));

        Member member = memberRepository.findById(DBrefreshToken.getMemberId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));


        return TokenResponse.builder()
                .accessToken(jwtProvider.createAccessToken(member.getUsername(), member.getRoles()))
                .refreshToken(request.getRefreshToken())
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
    public SignResponse getMember() throws Exception {
        String username = SecurityUtil.getCurrentMemberId();

        Member member = memberRepository.findByUsername(username)
                .orElseThrow(() -> new Exception("계정을 찾을 수 없습니다."));

        return new SignResponse(member);
    }
}
