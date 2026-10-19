package com.example.walletxbackend.service;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TokenIntrospectionService {
    private final JwtDecoder jwtDecoder;

    public Map<String, Object> introspect(String token) {
        if (token.isBlank() || token.length() > 8192) {
            return Map.of("active", false);
        }
        try {
            // Reuse exactly the validator used by auth's protected APIs: signature,
            // issuer, audience, database session, user ownership, and current role.
            var jwt = jwtDecoder.decode(token);
            if (jwt.getExpiresAt() == null || !jwt.getExpiresAt().isAfter(Instant.now())) {
                return Map.of("active", false);
            }
            var response = new LinkedHashMap<String, Object>();
            response.put("active", true);
            response.put("sub", jwt.getSubject());
            response.put("iss", jwt.getClaimAsString("iss"));
            response.put("aud", jwt.getAudience());
            response.put("exp", jwt.getExpiresAt().getEpochSecond());
            response.put("iat", jwt.getIssuedAt().getEpochSecond());
            response.put("roles", jwt.getClaimAsStringList("roles"));
            response.put("token_type", "Bearer");
            return response;
        } catch (JwtException invalidToken) {
            return Map.of("active", false);
        }
    }
}
