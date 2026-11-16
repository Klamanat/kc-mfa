package com.ktb.mfa;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** รหัสเชิญที่ admin ออกให้ user (เก็บเฉพาะ hash) ใช้ได้ครั้งเดียวและกรอกผิดได้จำกัดครั้ง */
@Entity
@Table(name = "mfa_invite")
public class MfaInvite {

    @Id
    @Column(length = 300)
    private String id;                 // realm|userId

    @Column(nullable = false, length = 64)
    private String codeHash;

    @Column(nullable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private int attempts;

    protected MfaInvite() {}

    public MfaInvite(String id, String codeHash, Instant expiresAt) {
        this.id = id;
        this.codeHash = codeHash;
        this.expiresAt = expiresAt;
    }

    public String getCodeHash() { return codeHash; }
    public Instant getExpiresAt() { return expiresAt; }
    public int getAttempts() { return attempts; }
    public void setAttempts(int v) { this.attempts = v; }
}
