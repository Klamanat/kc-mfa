package com.ktb.mfa;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** secret ที่สร้างแล้วแต่ user ยังไม่ยืนยันด้วยโค้ดแรก (เก็บใน DB เพื่อให้รันหลาย instance ได้) */
@Entity
@Table(name = "mfa_pending")
public class MfaPending {

    @Id
    @Column(length = 300)
    private String id;                 // realm|userId

    @Column(nullable = false, length = 512)
    private String secretEnc;

    @Column(nullable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private int attempts;

    protected MfaPending() {}

    public MfaPending(String id, String secretEnc, Instant expiresAt) {
        this.id = id;
        this.secretEnc = secretEnc;
        this.expiresAt = expiresAt;
    }

    public String getSecretEnc() { return secretEnc; }
    public Instant getExpiresAt() { return expiresAt; }
    public int getAttempts() { return attempts; }
    public void setAttempts(int v) { this.attempts = v; }
}
