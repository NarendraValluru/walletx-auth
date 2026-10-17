package com.example.walletxbackend.controller;

import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
public class AdminController {

    @GetMapping("/api/v1/admin/status")
    public Map<String, String> status() {
        return Map.of("status", "authorized");
    }
}
