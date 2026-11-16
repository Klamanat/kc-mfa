package com.ktb.mfa;

import java.time.Instant;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import jakarta.persistence.LockModeType;

public interface MfaPendingRepository extends JpaRepository<MfaPending, String> {

    /** SELECT ... FOR UPDATE: ให้การยืนยัน enroll ของ user เดียวกันทำทีละ request */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select p from MfaPending p where p.id = :id")
    Optional<MfaPending> findByIdForUpdate(@Param("id") String id);

    /** ลบ secret ที่ไม่มีใครมายืนยันจนหมดอายุ */
    @Modifying
    @Query("delete from MfaPending p where p.expiresAt < :now")
    int deleteExpired(@Param("now") Instant now);
}
