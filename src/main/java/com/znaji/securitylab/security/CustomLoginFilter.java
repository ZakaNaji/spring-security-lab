package com.znaji.securitylab.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import java.io.IOException;
import java.util.Map;

public class CustomLoginFilter extends AbstractAuthenticationProcessingFilter {

    private final ObjectMapper mapper = new ObjectMapper();

    public CustomLoginFilter() {
        super("/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        Map<String, String> body = mapper.readValue(request.getInputStream(), Map.class);
        String username = body.get("username");
        String password = body.get("password");
        UsernamePasswordAuthToken unAuthUser = new UsernamePasswordAuthToken(username, password);

        return getAuthenticationManager().authenticate(unAuthUser);
    }

}
