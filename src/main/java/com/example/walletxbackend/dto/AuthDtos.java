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

    public record Registration(@NotBlank @Size(max = 120) @Pattern(regexp = "[^\\p{Cc}]+") String fullName,
                               @NotBlank @Email @Size(max = 254) String email,
                               @NotBlank @Size(min = 12, max = 72) @Pattern(regexp = "[\\x00-\\x7F]+") String password) {}

    public record ForgotPassword(@NotBlank @Email @Size(max = 254) String email) {}

    public record ResetPassword(@NotBlank @Pattern(regexp = "[A-Za-z0-9_-]{43}") String token,
                                @NotBlank @Size(min = 12, max = 72) @Pattern(regexp = "[\\x00-\\x7F]+") String password) {}

    public record Profile(UUID id, String email, String role, String fullName) {
    }

    public record Tokens(String accessToken, String refreshToken, String tokenType, long expiresIn, Profile user) {
    }
}
