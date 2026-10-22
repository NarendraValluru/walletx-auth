package com.example.walletxbackend.service;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import java.net.URI;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

@Service
public class PasswordResetDelivery {
    private final ObjectProvider<JavaMailSender> mail;
    private final String mode, from, resetUrl;
    private final Path outbox;

    public PasswordResetDelivery(ObjectProvider<JavaMailSender> mail,
            @Value("${walletx.auth.reset.delivery}") String mode,
            @Value("${walletx.auth.reset.from}") String from,
            @Value("${walletx.auth.reset.url}") String resetUrl,
            @Value("${walletx.auth.reset.outbox}") String outbox) {
        this.mail=mail; this.mode=mode; this.from=from; this.resetUrl=resetUrl; this.outbox=Path.of(outbox);
    }

    @PostConstruct
    void validate() {
        var uri=URI.create(resetUrl);
        boolean local=java.util.Set.of("localhost","127.0.0.1","[::1]").contains(uri.getHost());
        if(uri.getHost()==null || uri.getUserInfo()!=null || uri.getFragment()!=null || uri.getQuery()!=null
                || !("https".equals(uri.getScheme()) || (local && "http".equals(uri.getScheme()))))
            throw new IllegalArgumentException("Configure an absolute HTTPS password reset URL (HTTP allowed on loopback)");
        if(!mode.equals("smtp") && !mode.equals("file")) throw new IllegalArgumentException("Reset delivery must be smtp or file");
        if(mode.equals("file") && !local) throw new IllegalArgumentException("File reset delivery is for loopback development only; use SMTP for deployment");
        if(mode.equals("smtp") && mail.getIfAvailable()==null) throw new IllegalArgumentException("Configure spring.mail.host for SMTP reset delivery");
    }

    public void send(String email,String token) {
        String text="A password reset was requested for your WalletX account.\n\n"
                +resetUrl+"#token="+token+"\n\nThis link expires in 15 minutes and can be used once."
                +" If you did not request this, ignore this email.\n";
        try {
            if(mode.equals("smtp")) {
                var message=new SimpleMailMessage();
                message.setFrom(from); message.setTo(email); message.setSubject("Reset your WalletX password"); message.setText(text);
                mail.getObject().send(message);
            } else {
                Files.createDirectories(outbox);
                // Private development mailbox, never exposed through an HTTP endpoint or response.
                Files.writeString(outbox.resolve(UUID.randomUUID()+".txt"),
                        "To: "+email+"\nSubject: Reset your WalletX password\n\n"+text,
                        StandardCharsets.UTF_8,StandardOpenOption.CREATE_NEW);
            }
        } catch(Exception failure) {
            // Never put the token, address, SMTP credentials or provider response in HTTP errors.
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Password reset delivery is temporarily unavailable");
        }
    }
}
