package com.znaji.securitylab.exception;

public class RefreshTokenReuseDetectedException extends RefreshTokenException{
    private final String familyId;

    public RefreshTokenReuseDetectedException(String familyId) {
        super("Refresh token reuse detected");
        this.familyId = familyId;
    }

    public String familyId() { return familyId; }
}
