package com.znaji.securitylab.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import java.io.IOException;
import java.util.Map;

public class CustomLoginFilter extends AbstractAuthenticationProcessingFilter {

    private final AuthenticationManager manager;
    private final ObjectMapper mapper = new ObjectMapper();

    public CustomLoginFilter(AuthenticationManager manager) {
        super("/login");
        this.manager = manager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        Map<String, String> body = mapper.readValue(request.getInputStream(), Map.class);
        String username = body.get("username");
        String password = body.get("password");
        UsernamePasswordAuthToken unAuthUser = new UsernamePasswordAuthToken(username, password);

        return manager.authenticate(unAuthUser);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.getWriter().write("""
                {"status":"success","message":"Logged in!"}
                """);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write("""
            {"status":"error","message":"Invalid credentials"}
        """);
    }
}
