package com.naveen.authService.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    // Generate a secure key
    SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    // Convert the key to a base64-encoded string for storage
    private final String jwtSecret = Base64.getEncoder().encodeToString(key.getEncoded());

    private final int jwtExpirationMs = 60*60*1000; // 1 minute

    public String generateToken(Authentication authentication) {
        String jwtToken = Jwts.builder()
                .setSubject(authentication.getName())
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
        return jwtToken;
    }

    public String extractUsername(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            logger.info("Token validated");
            return true;
        } catch (Exception e) {
            logger.error("Token Is Invalid");
            return false;
        }
    }
}
