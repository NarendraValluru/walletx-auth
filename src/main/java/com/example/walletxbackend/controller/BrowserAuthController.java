package com.example.walletxbackend.controller;

import com.example.walletxbackend.dto.AuthDtos.*;
import com.example.walletxbackend.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import java.time.Duration;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth/browser")
public class BrowserAuthController {
    private final AuthService service;
    @Value("${walletx.auth.browser.secure-cookie:false}") private boolean secureCookie;
    @Value("${walletx.auth.refresh-seconds}") private long refreshSeconds;
    public record BrowserTokens(String accessToken,String tokenType,long expiresIn,Profile user) {}

    @GetMapping("/csrf")
    public ResponseEntity<Map<String,String>> csrf(CsrfToken token) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(Map.of("token",token.getToken(),"headerName",token.getHeaderName()));
    }
    @PostMapping("/register")
    public ResponseEntity<Profile> register(@Valid @RequestBody Registration credentials) {
        return ResponseEntity.status(201).cacheControl(CacheControl.noStore()).body(service.register(credentials));
    }
    @PostMapping("/login")
    public ResponseEntity<BrowserTokens> login(@Valid @RequestBody Credentials credentials,
            @CookieValue(name="walletx_refresh",required=false) String previous) {
        Tokens tokens=service.login(credentials);
        if(validToken(previous)) service.logoutByRefresh(previous);
        return tokenResponse(tokens);
    }
    @PostMapping("/refresh")
    public ResponseEntity<BrowserTokens> refresh(@CookieValue(name="walletx_refresh",required=false) String refresh) {
        if(!validToken(refresh)) throw new BadCredentialsException("Invalid credentials or session");
        return tokenResponse(service.refresh(refresh));
    }
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@CookieValue(name="walletx_refresh",required=false) String refresh) {
        if(validToken(refresh)) service.logoutByRefresh(refresh);
        return ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE,cookie("",Duration.ZERO).toString())
                .cacheControl(CacheControl.noStore()).build();
    }
    private ResponseEntity<BrowserTokens> tokenResponse(Tokens tokens) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).header("Pragma","no-cache")
                .header(HttpHeaders.SET_COOKIE,cookie(tokens.refreshToken(),Duration.ofSeconds(refreshSeconds)).toString())
                .body(new BrowserTokens(tokens.accessToken(),tokens.tokenType(),tokens.expiresIn(),tokens.user()));
    }
    private ResponseCookie cookie(String value,Duration maxAge) {
        return ResponseCookie.from("walletx_refresh",value).httpOnly(true).secure(secureCookie)
                .sameSite("Lax").path("/").maxAge(maxAge).build();
    }
    private boolean validToken(String value) { return value!=null && value.matches("[A-Za-z0-9_-]{43}"); }
}
