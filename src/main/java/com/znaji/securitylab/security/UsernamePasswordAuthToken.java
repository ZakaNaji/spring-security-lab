package com.znaji.securitylab.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class UsernamePasswordAuthToken extends AbstractAuthenticationToken {

    private final Object principal;
    private Object credentials;

    // Constructor for UNAUTHENTICATED token (before login)
    public UsernamePasswordAuthToken(String username, String password) {
        super(null);
        this.principal = username;
        this.credentials = password;
        setAuthenticated(false);
    }

    // Constructor for AUTHENTICATED token
    public UsernamePasswordAuthToken(
            Object principal,
            Object credentials,
            Collection<? extends GrantedAuthority> authorities
    ) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        setAuthenticated(true);
    }


    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}
