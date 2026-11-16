package com.ktb.mfa;

import java.time.Instant;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import jakarta.persistence.LockModeType;

public interface MfaInviteRepository extends JpaRepository<MfaInvite, String> {

    /** SELECT ... FOR UPDATE: ให้การใช้รหัสเชิญของ user เดียวกันทำทีละ request (กันใช้ซ้ำ / นับครั้งผิดพลาด) */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select i from MfaInvite i where i.id = :id")
    Optional<MfaInvite> findByIdForUpdate(@Param("id") String id);

    @Modifying
    @Query("delete from MfaInvite i where i.expiresAt < :now")
    int deleteExpired(@Param("now") Instant now);
}
