package com.znaji.securitylab.security;

import java.time.Instant;

public final class RefreshTokenRecord {
    public enum Status { ACTIVE, USED, REVOKED }

    private final String token;
    private final String username;
    private final String familyId;
    private final Instant createdAt;
    private final Instant expiresAt;

    private volatile Status status;
    private volatile String replacedBy;

    public RefreshTokenRecord(String token, String username, String familyId,
                              Instant createdAt, Instant expiresAt) {
        this.token = token;
        this.username = username;
        this.familyId = familyId;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.status = Status.ACTIVE;
    }

    public String token() { return token; }
    public String username() { return username; }
    public String familyId() { return familyId; }
    public Instant expiresAt() { return expiresAt; }
    public Status status() { return status; }
    public String replacedBy() { return replacedBy; }

    public void markUsed(String newToken) {
        this.status = Status.USED;
        this.replacedBy = newToken;
    }

    public void revoke() { this.status = Status.REVOKED; }

}
