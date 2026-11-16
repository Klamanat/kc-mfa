package com.ktb.mfa;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import jakarta.persistence.LockModeType;

public interface MfaCredentialRepository extends JpaRepository<MfaCredential, String> {

    /** SELECT ... FOR UPDATE: ให้การตรวจ OTP ของ user เดียวกันทำทีละ request (นับครั้งผิดไม่หาย, โค้ดเดียวใช้ได้ครั้งเดียว) */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select c from MfaCredential c where c.id = :id")
    Optional<MfaCredential> findByIdForUpdate(@Param("id") String id);
}
