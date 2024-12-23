package com.project.securitypf.services.impl;

import com.project.securitypf.dto.JwtAuthenticationResponse;
import com.project.securitypf.dto.RefreshTokenRequest;
import com.project.securitypf.dto.SignUpRequest;
import com.project.securitypf.dto.SigninRequest;
import com.project.securitypf.entities.Role;
import com.project.securitypf.entities.User;
import com.project.securitypf.repositories.UserRepository;
import com.project.securitypf.services.AuthenticationService;
import com.project.securitypf.services.JWTService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.NoSuchElementException;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;

    private final JWTService jwtService;

    public User signup(SignUpRequest signUpRequest) {
        User user = new User();

        user.setEmail(signUpRequest.getEmail());
        user.setUsername(signUpRequest.getUsername());
        Role role = signUpRequest.getRole() != null ? signUpRequest.getRole() : Role.USER;
        user.setRole(role);
        user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));

        return userRepository.save(user);
    }
    public JwtAuthenticationResponse signin(SigninRequest signinRequest){
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(signinRequest.getEmail(), signinRequest.getPassword()));

        var user = userRepository.findByEmail(signinRequest.getEmail()).orElseThrow(() -> new IllegalArgumentException("Invalid email or password"));
        var jwt = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);

        JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();

        jwtAuthenticationResponse.setToken(jwt);
        jwtAuthenticationResponse.setRefreshToken(refreshToken);
        return jwtAuthenticationResponse;
    }

    public JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {
        String userEmail = jwtService.extractUserName(refreshTokenRequest.getToken());

        // Vérifie si l'email est extrait correctement
        if (userEmail == null || userEmail.isEmpty()) {
            throw new IllegalArgumentException("Invalid email extracted from the token");
        }

        // Recherche l'utilisateur par email et gère le cas où il n'existe pas
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new IllegalArgumentException("User with this email does not exist"));

        // Valide le token et génère un nouveau JWT
        if (jwtService.validateToken(refreshTokenRequest.getToken(), user)) {
            var jwt = jwtService.generateToken(user);

            JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();
            jwtAuthenticationResponse.setToken(jwt);
            jwtAuthenticationResponse.setRefreshToken(refreshTokenRequest.getToken());
            return jwtAuthenticationResponse;
        }

        // Retourne null si la validation échoue
        return null;
    }

}
