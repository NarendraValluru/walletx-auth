package com.example.walletxbackend.exception;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.web.bind.MethodArgumentNotValidException;

@RestControllerAdvice
public class AuthErrors {
    @ExceptionHandler(org.springframework.web.server.ResponseStatusException.class)
    ResponseEntity<ProblemDetail> status(org.springframework.web.server.ResponseStatusException failure) {
        return error(failure.getStatusCode().value(), failure.getReason());
    }
    @ExceptionHandler(BadCredentialsException.class)
    ResponseEntity<ProblemDetail> credentials() {
        return error(401, "Invalid credentials or session");
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    ResponseEntity<ProblemDetail> duplicate() {
        return error(409, "Unable to create account with the supplied details");
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<ProblemDetail> validation() {
        return error(400, "Invalid request. Registration requires a full name (maximum 120 characters). Use a valid email and a 12-72 character ASCII password; reset and refresh tokens must be 43 characters.");
    }

    private ResponseEntity<ProblemDetail> error(int status, String detail) {
        return ResponseEntity.status(status).body(ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(status), detail));
    }
}
