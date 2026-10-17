package com.example.walletxbackend.controller;

import com.example.walletxbackend.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.UUID;

import static com.example.walletxbackend.dto.AuthDtos.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final AuthService service;

    @PostMapping("/register")
    public ResponseEntity<Profile> register(@Valid @RequestBody Credentials c) {
        return ResponseEntity.status(201).body(service.register(c));
    }

    @PostMapping("/login")
    public ResponseEntity<Tokens> login(@Valid @RequestBody Credentials c) {
        return tokenResponse(service.login(c));
    }

    @PostMapping("/refresh")
    public ResponseEntity<Tokens> refresh(@Valid @RequestBody Refresh r) {
        return tokenResponse(service.refresh(r.refreshToken()));
    }

    @GetMapping("/me")
    public Profile me(@AuthenticationPrincipal Jwt jwt) {
        return service.me(UUID.fromString(jwt.getSubject()));
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@AuthenticationPrincipal Jwt jwt) {
        service.logout(UUID.fromString(jwt.getClaimAsString("sid")));
    }

    private ResponseEntity<Tokens> tokenResponse(Tokens t) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).header("Pragma", "no-cache").body(t);
    }
}
