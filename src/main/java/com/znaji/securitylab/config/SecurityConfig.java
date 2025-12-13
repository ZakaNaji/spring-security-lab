package com.znaji.securitylab.config;

import com.znaji.securitylab.security.CustomAuthProvider;
import com.znaji.securitylab.security.CustomLoginFilter;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

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
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AbstractAuthenticationProcessingFilter loginFilter) throws Exception {

        http
                .csrf(csrf -> csrf.disable()) // just to keep things simple for now
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/public/**").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/api/**").hasAnyRole("ADMIN", "USER")
                        .requestMatchers("/vip/**").access(customAuthz())
                        .anyRequest().authenticated()
                )
                .exceptionHandling(exceptionConfig -> exceptionConfig
                        .accessDeniedHandler(accessDeniedHandler())
                        .authenticationEntryPoint(authenticationEntryPoint())
                )
                .addFilterAt(loginFilter, UsernamePasswordAuthenticationFilter.class)
                .sessionManagement(sess ->
                        sess.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                //.securityContext(secContext -> secContext.requireExplicitSave(false))
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .clearAuthentication(true)
                        .logoutSuccessHandler(logoutSuccessHandler()))
        ;

        return http.build();
    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, authException) -> {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("""
            {"status":"unauthorized","message":"Authentication required"}
        """);
        };
    }

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        return (request, response, authentication) -> {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json");
            response.getWriter().write("""
            {"status":"success","message":"Logged out"}
        """);
        };
    }

    @Bean
    public AuthenticationSuccessHandler loginSuccessHandler() {
        return (request, response, authentication) -> {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json");
            response.getWriter().write("""
            {"status":"success","message":"Logged in!"}
        """);
        };
    }

    @Bean
    public AuthenticationFailureHandler loginFailureHandler() {
        return (request, response, exception) -> {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("""
            {"status":"fail","error":"Bad credentials"}
        """);
        };
    }
    @Bean
    public AbstractAuthenticationProcessingFilter loginFilter(
            AuthenticationManager authenticationManager,
            SecurityContextRepository securityContextRepository,
            AuthenticationSuccessHandler successHandler,
            AuthenticationFailureHandler failureHandler
    ) {
        CustomLoginFilter filter = new CustomLoginFilter();
        filter.setAuthenticationManager(authenticationManager);
        filter.setSecurityContextRepository(securityContextRepository);
        filter.setAuthenticationSuccessHandler(successHandler);
        filter.setAuthenticationFailureHandler(failureHandler);
        return filter;
    }


    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, ex) -> {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter().write("""
            {"status":"forbidden","message":"Access denied"}
            """);
        };
    }

    @Bean
    public AuthorizationManager<RequestAuthorizationContext> customAuthz() {
        return (authentication, context) -> {
            String name = authentication.get().getName();
            boolean granted = name.startsWith("VIP");
            return new AuthorizationDecision(granted);
        };
    }

    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    public SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new SessionFixationProtectionStrategy();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Temporary in-memory user store so we can verify the chain.
     * We'll replace this with custom auth in later steps.
     */
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
        UserDetails user = User.withUsername("user")
                .password(encoder.encode("password"))
                .roles("USER")
                .build();

        UserDetails admin = User.withUsername("admin")
                .password(encoder.encode("admin"))
                .roles("ADMIN")
                .build();

        UserDetails vip = User.withUsername("VIP")
                .password(encoder.encode("VIP"))
                .roles("VIP")
                .build();

        return new InMemoryUserDetailsManager(user, admin, vip);
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
