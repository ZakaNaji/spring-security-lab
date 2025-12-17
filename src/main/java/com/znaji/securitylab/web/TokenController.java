package com.znaji.securitylab.web;

import com.znaji.securitylab.security.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

@RestController
public class TokenController {

    private final RefreshTokenService refreshTokenService;
    private final UserDetailsService userDetailsService;
    private final JwtService jwtService;

    public TokenController(RefreshTokenService refreshTokenService, UserDetailsService userDetailsService, JwtService jwtService) {
        this.refreshTokenService = refreshTokenService;
        this.userDetailsService = userDetailsService;
        this.jwtService = jwtService;
    }

    @PostMapping("/refresh")
    public Map<String, String> refresh(@RequestBody Map<String, String> body) {
        String refreshToken = body.get("refreshToken");

        if (refreshToken == null || refreshToken.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing refreshToken");
        }

        RotationResult rotation = refreshTokenService.rotate(refreshToken);

        UserDetails user = userDetailsService.loadUserByUsername(rotation.username());
        Authentication auth = new UsernamePasswordAuthToken(
                user.getUsername(), null, user.getAuthorities()
        );


        String newAccessToken = jwtService.generateToken(auth);

        return Map.of(
                "accessToken", newAccessToken,
                "refreshToken", rotation.newRefreshToken()
        );
    }

    @PostMapping("/logout")
    public void logout(@RequestBody Map<String, String> body) {
        refreshTokenService.revokeToken(body.get("refreshToken"));
    }
}
