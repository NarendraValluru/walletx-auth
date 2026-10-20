package com.example.walletxbackend.service;
import com.example.walletxbackend.repository.UserRepository;
import com.example.walletxbackend.repository.SessionRepository;
import com.example.backendutil.auth.AuthUserEntity;
import com.example.backendutil.auth.AuthSessionEntity;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;

import java.security.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

import static com.example.walletxbackend.dto.AuthDtos.*;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository users;
    private final SessionRepository sessions;
    private final PasswordEncoder passwords;
    private final JwtEncoder encoder;
    @Value("${walletx.auth.issuer}")
    private String issuer;
    @Value("${walletx.auth.access-seconds}")
    private long accessSeconds;
    @Value("${walletx.auth.refresh-seconds}")
    private long refreshSeconds;
    private String dummyHash;

    @PostConstruct
    void initializeDummyHash() {
        dummyHash = passwords.encode(UUID.randomUUID().toString());
    }

    @Transactional
    public Profile register(Credentials c) {
        var u = users.saveAndFlush(new AuthUserEntity(normalize(c.email()), passwords.encode(c.password())));
        return profile(u);
    }

    // Persist failed-login counters even when authentication is rejected.
    @Transactional(noRollbackFor = BadCredentialsException.class)
    public Tokens login(Credentials c) {
        var u = users.lockByEmail(normalize(c.email())).orElse(null);
        boolean matches = passwords.matches(c.password(), u == null ? dummyHash : u.getPasswordHash());
        var now = Instant.now();
        if (u == null) throw invalid();
        if (u.getLockedUntil() != null && u.getLockedUntil().isAfter(now)) throw invalid();
        if (!matches) {
            u.setFailedAttempts(u.getFailedAttempts() + 1);
            if (u.getFailedAttempts() >= 5) {
                u.setLockedUntil(now.plusSeconds(900));
                u.setFailedAttempts(0);
            }
            throw invalid();
        }
        u.setFailedAttempts(0);
        u.setLockedUntil(null);
        var token = randomToken();
        var session = new AuthSessionEntity(u.getId(), hash(token), now.plusSeconds(refreshSeconds));
        sessions.saveAndFlush(session);
        return tokens(u, session, token);
    }

    @Transactional
    public Tokens refresh(String token) {
        var s = sessions.lockByRefreshHash(hash(token)).orElseThrow(AuthService::invalid);
        if (s.isRevoked() || !s.getExpiresAt().isAfter(Instant.now())) throw invalid();
        var u = users.findById(s.getUserId()).orElseThrow(AuthService::invalid);
        var next = randomToken();
        s.setRefreshHash(hash(next));
        sessions.flush();
        return tokens(u, s, next);
    }

    @Transactional
    public void logout(UUID sessionId) {
        sessions.lockById(sessionId).ifPresent(s -> s.setRevoked(true));
    }

    public Profile me(UUID userId) {
        return profile(users.findById(userId).orElseThrow(AuthService::invalid));
    }

    private Tokens tokens(AuthUserEntity u, AuthSessionEntity s, String refresh) {
        var now = Instant.now();
        var claims = JwtClaimsSet.builder().issuer(issuer).subject(u.getId().toString()).audience(List.of("walletx-api")).issuedAt(now).expiresAt(now.plusSeconds(accessSeconds)).id(UUID.randomUUID().toString()).claim("sid", s.getId().toString()).claim("roles", List.of(u.getRole())).build();
        var jwt = encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims));
        return new Tokens(jwt.getTokenValue(), refresh, "Bearer", accessSeconds, profile(u));
    }

    private static Profile profile(AuthUserEntity u) {
        return new Profile(u.getId(), u.getEmail(), u.getRole());
    }

    private static String normalize(String email) {
        return email.strip().toLowerCase(Locale.ROOT);
    }

    private static BadCredentialsException invalid() {
        return new BadCredentialsException("Invalid credentials or session");
    }

    private static String randomToken() {
        byte[] b = new byte[32];
        new SecureRandom().nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static String hash(String token) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
