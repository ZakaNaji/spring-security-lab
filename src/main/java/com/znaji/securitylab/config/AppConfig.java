package com.znaji.securitylab.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(
        basePackages = "com.znaji.securitylab",
        excludeFilters = {
                @ComponentScan.Filter(org.springframework.stereotype.Controller.class),
                @ComponentScan.Filter(org.springframework.web.bind.annotation.RestController.class)
        })
public class AppConfig {
    // Root beans (services, repositories, etc.) can go here later.
}