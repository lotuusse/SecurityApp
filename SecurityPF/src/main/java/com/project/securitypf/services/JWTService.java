package com.project.securitypf.services;

import com.project.securitypf.entities.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;


public interface JWTService {
    String extractUserName(String token);
    String generateToken(UserDetails userDetails);
    boolean validateToken(String token, UserDetails userDetails);

    String generateRefreshToken(Map<String, Object> extractClaims, UserDetails userDetails);
//String generateRefreshToken(UserDetails userDetails);
}
