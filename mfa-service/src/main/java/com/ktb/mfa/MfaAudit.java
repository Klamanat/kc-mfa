package com.ktb.mfa;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** บันทึกเหตุการณ์ (เพิ่มอย่างเดียว) */
@Entity
@Table(name = "mfa_audit")
public class MfaAudit {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Instant at;

    @Column(nullable = false, length = 40)
    private String event;

    @Column(nullable = false, length = 128)
    private String realm;

    @Column(nullable = false, length = 64)
    private String userId;

    @Column(nullable = false, length = 128)
    private String clientId;

    @Column(length = 64)
    private String actor;

    @Column(length = 64)
    private String remoteIp;

    @Column(length = 200)
    private String detail;

    protected MfaAudit() {}

    public MfaAudit(Instant at, String event, String realm, String userId, String clientId,
                    String actor, String remoteIp, String detail) {
        this.at = at;
        this.event = event;
        this.realm = realm;
        this.userId = userId;
        this.clientId = clientId;
        this.actor = actor;
        this.remoteIp = remoteIp;
        this.detail = detail;
    }
}
