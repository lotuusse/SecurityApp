package com.project.securitypf.services.impl;

import com.project.securitypf.services.JWTService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JWTServiceImpl implements JWTService {

    private Key secretKey;


    @PostConstruct
    public void init() {
        this.secretKey = generateSecretKey();  // Génère la clé secrète lors de l'initialisation du service
    }


    private Key generateSecretKey() {
        SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[32];
        random.nextBytes(keyBytes);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String generateToken(UserDetails userDetails) {
        return Jwts.builder().setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60* 24))
                .signWith(secretKey ,SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken(Map<String, Object> extractClaims, UserDetails userDetails) {
        return Jwts.builder().setClaims(extractClaims).setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 606800000))
                .signWith(secretKey ,SignatureAlgorithm.HS256)
                .compact();
    }


    private <T> T extractClaim(String token, Function<Claims, T> claimsResolvers) {
        final Claims claims = extractAllClaims(token);
        return claimsResolvers.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody();
    }

    // Valide le token
    public boolean validateToken(String token, UserDetails userDetails) {
//        String tokenUsername = Jwts.parserBuilder()
//                .setSigningKey(secretKey) // Vérification avec la même clé
//                .build()
//                .parseClaimsJws(token)
//                .getBody()
//                .getSubject();
//        return username.equals(tokenUsername) && !isTokenExpired(token);
        final String username = extractUserName(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    // Vérifie si le token a expiré
    private boolean isTokenExpired(String token) {
//        Date expiration = Jwts.parserBuilder()
//                .setSigningKey(secretKey)
//                .build()
//                .parseClaimsJws(token)
//                .getBody()
//                .getExpiration();
//        return expiration.before(new Date());
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }


}






























