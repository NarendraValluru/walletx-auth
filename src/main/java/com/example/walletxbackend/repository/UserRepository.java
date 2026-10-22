package com.example.walletxbackend.repository;

import com.example.backendutil.auth.AuthUserEntity;
import org.springframework.data.jpa.repository.*;
import jakarta.persistence.LockModeType;

import java.util.*;

public interface UserRepository extends JpaRepository<AuthUserEntity, UUID> {
    Optional<AuthUserEntity> findByEmail(String email);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from AuthUser u where u.email = :email")
    Optional<AuthUserEntity> lockByEmail(String email);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from AuthUser u where u.resetTokenHash = :hash")
    Optional<AuthUserEntity> lockByResetTokenHash(String hash);
}
