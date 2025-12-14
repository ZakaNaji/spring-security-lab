package com.znaji.securitylab.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;

@Service
public class JwtService {

    private static final String SECRET = "M1FhS3ZyZVZ6b3pQbXJjRkR2b0R4QkJ1bFZ0RkR1R1A3a1ZxZQ==";
    private static final long EXPIRATION = 60 * 60 * 1000; // 1 hour

    private final Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET));

    public String generateToken(Authentication auth) {
        return Jwts.builder()
                .setSubject(auth.getName())
                .claim("roles", auth.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION))
                .signWith(key)
                .compact();
    }

    public Claims parseToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
