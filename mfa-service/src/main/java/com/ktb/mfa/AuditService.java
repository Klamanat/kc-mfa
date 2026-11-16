package com.ktb.mfa;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * บันทึกเหตุการณ์ลง DB (ตาราง mfa_audit) และ log (logger "mfa.audit") ใน transaction เดียวกับการกระทำที่เรียกมา
 * ค่าทุกตัวที่ใส่ลง log มาจาก token ที่ตรวจแล้ว ค่าที่ validate แล้ว (userId, actor) หรือค่าคงที่ ไม่มีข้อความจาก request ตรงๆ
 */
@Service
public class AuditService {

    private static final Logger LOG = LoggerFactory.getLogger("mfa.audit");

    /** ผู้กระทำ: client จาก token, ชื่อผู้ดูแลที่แจ้งมา (null สำหรับเหตุการณ์ที่ไม่ใช่ admin), IP ของผู้เรียก */
    public record Ctx(String clientId, String actor, String ip) {}

    private final MfaAuditRepository repo;

    public AuditService(MfaAuditRepository repo) {
        this.repo = repo;
    }

    @Transactional
    public void record(String event, String realm, String userId, Ctx ctx, String detail) {
        repo.save(new MfaAudit(Instant.now(), event, realm, userId, ctx.clientId(), ctx.actor(), ctx.ip(), detail));
        LOG.info("event={} realm={} user={} client={} actor={} ip={} detail={}",
                event, realm, userId, ctx.clientId(), ctx.actor() == null ? "-" : ctx.actor(), ctx.ip(), detail);
    }

    @Transactional(readOnly = true)
    public long countSince(String event, String clientId, Instant since) {
        return repo.countByEventAndClientIdAndAtAfter(event, clientId, since);
    }
}
