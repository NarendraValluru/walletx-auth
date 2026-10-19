package com.example.walletxbackend.controller;

import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.example.walletxbackend.service.TokenIntrospectionService;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/internal/token")
public class TokenIntrospectionController {
    private final TokenIntrospectionService service;

    @PostMapping(value = "/introspect", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map<String, Object>> introspect(@RequestParam String token) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header("Pragma", "no-cache").body(service.introspect(token));
    }
}
