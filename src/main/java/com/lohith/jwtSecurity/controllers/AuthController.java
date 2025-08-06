package com.lohith.jwtSecurity.controllers;


import com.lohith.jwtSecurity.dto.LoginRequestDto;
import com.lohith.jwtSecurity.dto.LoginResponseDto;
import com.lohith.jwtSecurity.dto.SignUpResponseDto;
import com.lohith.jwtSecurity.services.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(
            @RequestBody LoginRequestDto req
    ) {
        return ResponseEntity.ok(authService.login(req));
    }

    @PostMapping("/register")
    public ResponseEntity<SignUpResponseDto> Signup(
            @RequestBody LoginRequestDto req
    ) {
        SignUpResponseDto res=authService.signUp(req);
        return ResponseEntity.ok(res);
    }


}
