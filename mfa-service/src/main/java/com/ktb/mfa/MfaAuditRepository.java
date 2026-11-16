package com.ktb.mfa;

import java.time.Instant;

import org.springframework.data.jpa.repository.JpaRepository;

public interface MfaAuditRepository extends JpaRepository<MfaAudit, Long> {

    /** ใช้จำกัดจำนวนครั้งที่ admin client หนึ่งทำเหตุการณ์ชนิดหนึ่งต่อชั่วโมง */
    long countByEventAndClientIdAndAtAfter(String event, String clientId, Instant since);
}
