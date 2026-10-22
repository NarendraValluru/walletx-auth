package com.example.walletxbackend.repository;

import com.example.backendutil.auth.AuthSessionEntity;
import org.springframework.data.jpa.repository.*;
import jakarta.persistence.LockModeType;

import java.util.*;

public interface SessionRepository extends JpaRepository<AuthSessionEntity, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select s from AuthSession s where s.refreshHash = :hash")
    Optional<AuthSessionEntity> lockByRefreshHash(String hash);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select s from AuthSession s where s.id = :id")
    Optional<AuthSessionEntity> lockById(UUID id);

    @Modifying
    @Query("update AuthSession s set s.revoked = true where s.userId = :userId and s.revoked = false")
    int revokeAllByUserId(UUID userId);
}
