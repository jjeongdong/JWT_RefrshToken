package com.example.springsecurity_jwt.controller;

import com.example.springsecurity_jwt.dto.RegisterRequest;
import com.example.springsecurity_jwt.dto.SignRequest;
import com.example.springsecurity_jwt.dto.SignResponse;
import com.example.springsecurity_jwt.service.SignService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class SignController {

    private final SignService memberService;

    @PostMapping("/login")
    public ResponseEntity<SignResponse> login(@RequestBody SignRequest request) {
        return new ResponseEntity<>(memberService.login(request), HttpStatus.OK);
    }

    @PostMapping("/register")
    public ResponseEntity<Boolean> register(@RequestBody RegisterRequest request) throws Exception {
        return new ResponseEntity<>(memberService.register(request), HttpStatus.OK);
    }

    @GetMapping("/user/get")
    public ResponseEntity<SignResponse> getMember(@RequestParam String username) throws Exception {
        return new ResponseEntity<>( memberService.getMember(username), HttpStatus.OK);
    }

    @GetMapping("/admin/get")
    public ResponseEntity<SignResponse> getMemberForAdmin(@RequestParam String username) throws Exception {
        return new ResponseEntity<>( memberService.getMember(username), HttpStatus.OK);
    }
}
