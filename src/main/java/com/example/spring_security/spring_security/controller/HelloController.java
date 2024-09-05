package com.example.spring_security.spring_security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/hello")
public class HelloController {
    @GetMapping("/world")
    public String helloWorld() {
        return "Hello World!";
    }

    @GetMapping("/eledevo")
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN')") // Check Role
    public String helloEledevo() {
        return "Hello Eledevo!";
    }

    @GetMapping("/vietnam")
    @PreAuthorize("hasAuthority('management:read')") // Check permission
    public String helloVietNam() {
        return "Hello Việt Nam!";
    }
}
