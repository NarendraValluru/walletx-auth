package com.example.walletxbackend.config;

import com.example.walletxbackend.repository.UserRepository;
import com.example.walletxbackend.repository.SessionRepository;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.server.resource.authentication.*;
import com.nimbusds.jose.jwk.source.ImmutableSecret;

import java.util.*;
import java.time.Instant;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    SecretKeySpec jwtKey(@Value("${walletx.auth.secret}") String secret) {
        byte[] bytes = Base64.getDecoder().decode(secret);
        if (bytes.length < 64)
            throw new IllegalArgumentException("WALLETX_JWT_SECRET requires at least 64 random bytes, Base64 encoded");
        return new SecretKeySpec(bytes, "HmacSHA256");
    }

    @Bean
    JwtEncoder jwtEncoder(SecretKeySpec key) {
        return new NimbusJwtEncoder(new ImmutableSecret<>(key));
    }

    @Bean
    JwtDecoder jwtDecoder(SecretKeySpec key, SessionRepository sessions, UserRepository users,
                          @Value("${walletx.auth.issuer}") String issuer) {
        var decoder = NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build();
        OAuth2TokenValidator<Jwt> sessionValidator = jwt -> {
            try {
                var s = sessions.findById(UUID.fromString(jwt.getClaimAsString("sid"))).orElseThrow();
                var u = users.findById(s.getUserId()).orElseThrow();
                if (!s.isRevoked() && s.getExpiresAt().isAfter(Instant.now()) && s.getUserId().toString().equals(jwt.getSubject())
                        && jwt.getClaimAsStringList("roles").equals(List.of(u.getRole())) && jwt.getAudience().contains("walletx-api"))
                    return OAuth2TokenValidatorResult.success();
            } catch (RuntimeException ignored) {
            }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token"));
        };
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer), sessionValidator));
        return decoder;
    }

    @Bean
    SecurityFilterChain security(HttpSecurity http,
            @Value("${walletx.auth.browser.secure-cookie:false}") boolean secureCookie) throws Exception {
        var roles = new JwtGrantedAuthoritiesConverter();
        roles.setAuthoritiesClaimName("roles");
        roles.setAuthorityPrefix("ROLE_");
        var converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(roles);
        var csrfRepository=new org.springframework.security.web.csrf.CookieCsrfTokenRepository();
        csrfRepository.setCookieCustomizer(c -> c.httpOnly(true).secure(secureCookie).sameSite("Lax").path("/"));
        return http.csrf(c -> c.csrfTokenRepository(csrfRepository)
                        .ignoringRequestMatchers(request -> !request.getServletPath().startsWith("/api/v1/auth/browser/"))
                        .withObjectPostProcessor(new org.springframework.security.config.ObjectPostProcessor<org.springframework.security.web.csrf.CsrfFilter>() {
                            @Override public <O extends org.springframework.security.web.csrf.CsrfFilter> O postProcess(O filter) {
                                filter.setAccessDeniedHandler((request,response,failure) -> response.setStatus(403));
                                return filter;
                            }
                        }))
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a
                        .requestMatchers(org.springframework.http.HttpMethod.POST, "/api/v1/auth/register", "/api/v1/auth/login", "/api/v1/auth/refresh").permitAll()
                        .requestMatchers("/api/v1/auth/browser/**").permitAll()
                        .requestMatchers("/actuator/health").permitAll()
                        .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .oauth2ResourceServer(o -> o.jwt(j -> j.jwtAuthenticationConverter(converter)))
                .headers(h -> h.frameOptions(f -> f.deny()))
                .build();
    }
}
