package com.znaji.securitylab.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/public/hello")
    public String publicHello() {
        return "Hello from public endpoint";
    }

    @GetMapping("/api/hello")
    public String apiHello() {
        return "Hello from secured API";
    }
}