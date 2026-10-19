package com.example.walletxbackend.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class IntrospectionSecurityConfig {
    @Bean
    @Order(1)
    SecurityFilterChain introspectionSecurity(HttpSecurity http, PasswordEncoder passwordEncoder,
            @Value("${walletx.introspection.client-id}") String clientId,
            @Value("${walletx.introspection.client-secret}") String clientSecret) throws Exception {
        if (clientId.isBlank() || clientSecret.length() < 32) {
            throw new IllegalArgumentException("Configure an introspection client ID and a private secret of at least 32 characters; run walletx-finance/configure-auth-link.ps1 locally");
        }
        var clients = new InMemoryUserDetailsManager(User.withUsername(clientId)
                .password(passwordEncoder.encode(clientSecret)).roles("INTROSPECT").build());
        return http.securityMatcher("/api/v1/internal/token/introspect")
                .csrf(csrf -> csrf.disable())
                .requestCache(cache -> cache.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .userDetailsService(clients)
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers(HttpMethod.POST, "/api/v1/internal/token/introspect").hasRole("INTROSPECT")
                        .anyRequest().denyAll())
                .httpBasic(Customizer.withDefaults())
                .build();
    }
}
