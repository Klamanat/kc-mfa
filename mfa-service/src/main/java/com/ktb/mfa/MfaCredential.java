package com.ktb.mfa;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** MFA ของ user หนึ่งคนใน realm หนึ่ง (key = realm|userId โดย userId คือ claim "sub" ของ Keycloak) */
@Entity
@Table(name = "mfa_credential")
public class MfaCredential {

    @Id
    @Column(length = 300)
    private String id;

    @Column(nullable = false, length = 128)
    private String realm;

    @Column(nullable = false, length = 64)
    private String userId;

    @Column(nullable = false, length = 512)
    private String secretEnc;          // AES-GCM(base64)

    @Column(nullable = false)
    private long lastUsedStep;         // กัน replay: โค้ดที่ใช้แล้วใช้ซ้ำไม่ได้

    @Column(nullable = false)
    private int failedAttempts;

    private Instant lockedUntil;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    protected MfaCredential() {}

    public MfaCredential(String realm, String userId, String secretEnc, long lastUsedStep) {
        this.id = key(realm, userId);
        this.realm = realm;
        this.userId = userId;
        this.secretEnc = secretEnc;
        this.lastUsedStep = lastUsedStep;
    }

    public static String key(String realm, String userId) {
        return realm + "|" + userId;
    }

    public String getSecretEnc() { return secretEnc; }
    public long getLastUsedStep() { return lastUsedStep; }
    public void setLastUsedStep(long v) { this.lastUsedStep = v; }
    public int getFailedAttempts() { return failedAttempts; }
    public void setFailedAttempts(int v) { this.failedAttempts = v; }
    public Instant getLockedUntil() { return lockedUntil; }
    public void setLockedUntil(Instant v) { this.lockedUntil = v; }
}
