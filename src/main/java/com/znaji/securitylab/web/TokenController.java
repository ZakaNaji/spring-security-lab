package com.znaji.securitylab.web;

import com.znaji.securitylab.security.JwtService;
import com.znaji.securitylab.security.RefreshToken;
import com.znaji.securitylab.security.RefreshTokenService;
import com.znaji.securitylab.security.UsernamePasswordAuthToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

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

        RefreshToken rt = refreshTokenService.validate(refreshToken);

        UserDetails user = userDetailsService.loadUserByUsername(rt.getUsername());
        Authentication auth =
                new UsernamePasswordAuthToken(
                        user.getUsername(),
                        null,
                        user.getAuthorities()
                );

        String newAccessToken = jwtService.generateToken(auth);
        return Map.of("accessToken", newAccessToken);
    }

    @PostMapping("/logout")
    public void logout(@RequestBody Map<String, String> body) {
        refreshTokenService.revoke(body.get("refreshToken"));
    }
}
