package com.znaji.securitylab.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@ComponentScan(basePackages = "com.znaji.securitylab.web")
@EnableWebMvc
public class WebConfig implements WebMvcConfigurer {
    // For now we keep it minimal; later we can add formatters, message converters, etc.
}