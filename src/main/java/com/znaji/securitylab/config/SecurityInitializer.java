package com.znaji.securitylab.config;

import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;

public class SecurityInitializer extends AbstractSecurityWebApplicationInitializer {
    // Empty on purpose.
    // Just by extending this, we register the springSecurityFilterChain filter.
}
