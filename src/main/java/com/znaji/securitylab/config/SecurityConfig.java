package com.znaji.securitylab.config;

import com.znaji.securitylab.security.CustomAuthProvider;
import com.znaji.securitylab.security.CustomLoginFilter;
import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

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

        AbstractAuthenticationProcessingFilter loginFilter = new CustomLoginFilter(authenticationManager());
        loginFilter.setSecurityContextRepository(securityContextRepository());
        loginFilter.setAuthenticationSuccessHandler(((request, response, authentication) -> {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json");
            response.getWriter().write("""
                {"status":"success","message":"Logged in!"}
                """);
        }));

        loginFilter.setAuthenticationFailureHandler((request, response, exception) -> {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("""
                {"status":"fail","error":"Bad credentials"}
                """);
        });
        //loginFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy());


        http
                .csrf(csrf -> csrf.disable()) // just to keep things simple for now
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/public/**").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterAt(loginFilter, UsernamePasswordAuthenticationFilter.class)
                .sessionManagement(sess ->
                        sess.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                //.securityContext(secContext -> secContext.requireExplicitSave(false))
        ;

        return http.build();
    }

    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    public SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new SessionFixationProtectionStrategy();
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
