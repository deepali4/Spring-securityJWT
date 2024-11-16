package com.spring.project.Jwt.Services;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtil {
    @Value("${spring.auth.workflow.jwt.secret}")
    private String SecrateKey;

    public String generateToken(String userName) {
        long nowMillis = System.currentTimeMillis();
        long expMillis = nowMillis+1000*60*60;
        Date expDate = new Date(expMillis);
        System.out.println(SecrateKey);

        return Jwts.builder()
                .setSubject(userName)
                .setIssuedAt(new Date(nowMillis))
                .setExpiration(expDate)
                .signWith(SignatureAlgorithm.HS256,SecrateKey)
                .compact();
    }

    public boolean validateToken(String token) throws Exception {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(SecrateKey)
                    .parseClaimsJws(token)
                    .getBody();
            return true;
        } catch (ExpiredJwtException e) {
            throw new Exception("Token has expired", e);
        } catch (UnsupportedJwtException e) {
            throw new Exception("Unsupported JWT token", e);
        } catch (MalformedJwtException e) {
            throw new Exception("Invalid JWT token", e);
        } catch (SignatureException e) {
            throw new Exception("Invalid JWT signature", e);
        } catch (Exception e) {
            throw new Exception("Token validation failed", e);
        }
    }

    public String extractUserId(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(SecrateKey)
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }
}