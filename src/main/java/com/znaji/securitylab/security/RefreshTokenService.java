package com.znaji.securitylab.security;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RefreshTokenService {
    private final Map<String, RefreshToken> store = new ConcurrentHashMap<>();
    private static final long REFRESH_TTL_DAYS = 7;

    public String createRefreshToken(String username) {
        String token = UUID.randomUUID().toString();

        RefreshToken refreshToken = new RefreshToken(
                token,
                username,
                Instant.now().plus(REFRESH_TTL_DAYS, ChronoUnit.DAYS)
        );

        store.put(token, refreshToken);
        return token;
    }

    public RefreshToken validate(String token) {
        RefreshToken rt = store.get(token);

        if (rt == null) {
            throw new RuntimeException("Invalid refresh token");
        }

        if (rt.getExpiresAt().isBefore(Instant.now())) {
            store.remove(token);
            throw new RuntimeException("Expired refresh token");
        }

        return rt;
    }

    public void revoke(String token) {
        store.remove(token);
    }
}
