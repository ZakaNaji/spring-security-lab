package com.znaji.securitylab.security;

import com.znaji.securitylab.exception.RefreshTokenException;
import com.znaji.securitylab.exception.RefreshTokenReuseDetectedException;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RefreshTokenService {
    private static final Duration REFRESH_TTL = Duration.ofDays(7);
    // token -> record
    private final ConcurrentHashMap<String, RefreshTokenRecord> tokens = new ConcurrentHashMap<>();
    // familyId -> set of tokens (for fast family revocation)
    private final ConcurrentHashMap<String, Set<String>> families = new ConcurrentHashMap<>();


    public String issueInitialRefreshToken(String username) {
        String familyId = UUID.randomUUID().toString();
        return issueRefreshToken(username, familyId);
    }

    /**
     * Validate + rotate refresh token.
     * If token is USED -> reuse detected -> revoke entire family.
     */
    public RotationResult rotate(String presentedToken) {
        RefreshTokenRecord record = tokens.get(presentedToken);

        if (record == null) {
            throw new RefreshTokenException("Invalid refresh token");
        }

        if (record.expiresAt().isBefore(Instant.now())) {
            // Expired: revoke this token (and optionally family)
            record.revoke();
            throw new RefreshTokenException("Expired refresh token");
        }

        // Reuse detection
        if (record.status() == RefreshTokenRecord.Status.USED) {
            // Someone is trying to reuse a token that was already rotated.
            revokeFamily(record.familyId());
            throw new RefreshTokenReuseDetectedException(record.familyId());
        }

        if (record.status() == RefreshTokenRecord.Status.REVOKED) {
            throw new RefreshTokenException("Revoked refresh token");
        }

        // Rotation: mark old as USED, issue new one in same family
        String newToken = issueRefreshToken(record.username(), record.familyId());
        record.markUsed(newToken);

        return new RotationResult(record.username(), record.familyId(), newToken);
    }

    public void revokeFamily(String familyId) {
        Set<String> familyTokens = families.getOrDefault(familyId, Set.of());
        for (String t : familyTokens) {
            revokeToken(t);
        }
    }

    public void revokeToken(String token) {
        RefreshTokenRecord r = tokens.get(token);
        if (r != null) r.revoke();
    }

    private String issueRefreshToken(String username, String familyId) {
        String token = UUID.randomUUID().toString(); // lab: ok. prod: use SecureRandom bytes
        Instant now = Instant.now();
        RefreshTokenRecord record = new RefreshTokenRecord(
                token, username, familyId, now, now.plus(REFRESH_TTL)
        );

        tokens.put(token, record);
        families.computeIfAbsent(familyId, k -> ConcurrentHashMap.newKeySet()).add(token);

        return token;
    }

}
