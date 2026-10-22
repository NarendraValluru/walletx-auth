package com.example.walletxbackend.controller;

import com.example.walletxbackend.dto.AuthDtos.*;
import com.example.walletxbackend.service.PasswordResetService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import java.util.Map;
import org.springframework.web.server.ResponseStatusException;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/api/v1/auth/browser")
public class PasswordResetController {
    private final PasswordResetService service;

    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String,String>> forgot(@Valid @RequestBody ForgotPassword request) {
        try { service.request(request.email()); }
        catch(ResponseStatusException failure) {
            if(failure.getStatusCode()!=HttpStatus.SERVICE_UNAVAILABLE) throw failure;
            // Keep the same response for existing and unknown accounts, including delivery failures.
            log.error("Password reset delivery failed. Check the configured mailbox or SMTP service.");
        }
        return ResponseEntity.accepted().cacheControl(CacheControl.noStore())
                .body(Map.of("message","If an account exists for this email, a password reset link will be sent. Please check your inbox."));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Void> reset(@Valid @RequestBody ResetPassword request) {
        service.reset(request.token(),request.password());
        return ResponseEntity.noContent().cacheControl(CacheControl.noStore()).build();
    }
}
