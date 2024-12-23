package com.project.securitypf.services;

import com.project.securitypf.dto.JwtAuthenticationResponse;
import com.project.securitypf.dto.RefreshTokenRequest;
import com.project.securitypf.dto.SignUpRequest;
import com.project.securitypf.dto.SigninRequest;
import com.project.securitypf.entities.Role;
import com.project.securitypf.entities.User;

public interface AuthenticationService {

    User signup(SignUpRequest signUpRequest);

    JwtAuthenticationResponse signin(SigninRequest signinRequest);

    JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);

}
