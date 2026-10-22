package com.example.walletxbackend.service;

import com.example.walletxbackend.repository.UserRepository;
import com.example.walletxbackend.repository.SessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import java.security.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

@Service
@RequiredArgsConstructor
public class PasswordResetService {
    private final UserRepository users;
    private final SessionRepository sessions;
    private final PasswordEncoder passwords;
    private final PasswordResetDelivery delivery;

    @Transactional
    public void request(String email) {
        var user=users.lockByEmail(email.strip().toLowerCase(Locale.ROOT)).orElse(null);
        var now=Instant.now();
        if(user==null || (user.getResetRequestedAt()!=null && user.getResetRequestedAt().plusSeconds(60).isAfter(now))) return;
        byte[] bytes=new byte[32]; new SecureRandom().nextBytes(bytes);
        String token=Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        user.setResetTokenHash(hash(token));
        user.setResetExpiresAt(now.plusSeconds(900));
        user.setResetRequestedAt(now);
        users.flush();
        delivery.send(user.getEmail(),token);
    }

    @Transactional
    public void reset(String token,String password) {
        var user=users.lockByResetTokenHash(hash(token)).orElseThrow(PasswordResetService::invalid);
        if(user.getResetExpiresAt()==null || !user.getResetExpiresAt().isAfter(Instant.now())) throw invalid();
        user.setPasswordHash(passwords.encode(password));
        user.setResetTokenHash(null); user.setResetExpiresAt(null);
        user.setFailedAttempts(0); user.setLockedUntil(null);
        sessions.revokeAllByUserId(user.getId());
    }
    private static ResponseStatusException invalid() {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST,"This reset link is invalid or expired. Request a new link.");
    }
    private static String hash(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch(NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
}
