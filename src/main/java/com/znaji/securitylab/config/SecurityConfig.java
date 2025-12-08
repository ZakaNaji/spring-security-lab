package com.znaji.securitylab.config;

import com.znaji.securitylab.security.CustomAuthProvider;
import com.znaji.securitylab.security.CustomLoginFilter;
import jakarta.servlet.Filter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Minimal SecurityFilterChain:
     * - /public/** is open
     * - everything else requires authentication
     * - HTTP Basic for now (we'll replace with our own flow later)
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        Filter loginFilter = new CustomLoginFilter(authenticationManager());
        http
                .csrf(csrf -> csrf.disable()) // just to keep things simple for now
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/public/**").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterAt(loginFilter, UsernamePasswordAuthenticationFilter.class)
                .sessionManagement(sess -> sess.disable());

        return http.build();
    }

    /**
     * Temporary in-memory user store so we can verify the chain.
     * We'll replace this with custom auth in later steps.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user")
                .password("{noop}password") // {noop} = no encoder, ok for tests
                .roles("USER")
                .build();

        UserDetails admin = User.withUsername("admin")
                .password("{noop}admin")
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    public CustomAuthProvider customAuthProvider() {
        return new CustomAuthProvider();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return authentication -> {
            if (customAuthProvider().supports(authentication.getClass())) {
                return customAuthProvider().authenticate(authentication);
            }
            throw new IllegalArgumentException("No provider found");
        };
    }
}
