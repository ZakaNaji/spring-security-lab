package com.znaji.securitylab.security;

import java.time.Instant;

public class RefreshToken {
    private final String token;
    private final String username;
    private final Instant expiresAt;

    public RefreshToken(String token, String username, Instant expiresAt) {
        this.token = token;
        this.username = username;
        this.expiresAt = expiresAt;
    }

    public String getToken() {
        return token;
    }

    public String getUsername() {
        return username;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }
}
