package com.example.walletxbackend.dto;

import jakarta.validation.constraints.*;

import java.util.UUID;

public final class AuthDtos {
    private AuthDtos() {
    }

    public record Credentials(@NotBlank @Email @Size(max = 254) String email,
                              @NotBlank @Size(min = 12, max = 72) @Pattern(regexp = "[\\x00-\\x7F]+", message = "must contain ASCII characters only") String password) {
    }

    public record Refresh(@NotBlank @Size(min = 43, max = 43) String refreshToken) {
    }

    public record Profile(UUID id, String email, String role) {
    }

    public record Tokens(String accessToken, String refreshToken, String tokenType, long expiresIn, Profile user) {
    }
}
