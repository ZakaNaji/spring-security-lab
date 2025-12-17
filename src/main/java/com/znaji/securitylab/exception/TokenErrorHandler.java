package com.znaji.securitylab.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice
public class TokenErrorHandler {

    @ExceptionHandler(RefreshTokenReuseDetectedException.class)
    public ResponseEntity<Map<String, String>> handleReuse(RefreshTokenReuseDetectedException ex) {
        // 409 Conflict is common here
        return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                "status", "compromised",
                "message", "Refresh token reuse detected. Please re-authenticate."
        ));
    }

    @ExceptionHandler(RefreshTokenException.class)
    public ResponseEntity<Map<String, String>> handleToken(RefreshTokenException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                "status", "fail",
                "message", ex.getMessage()
        ));
    }
}
