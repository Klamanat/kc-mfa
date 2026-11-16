package com.ktb.kcmfa.starter;

import java.io.Serializable;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * สถานะฝั่ง server ของ login ผ่าน OAuth provider ภายนอก (Authorization Code + PKCE) มี 2 ชนิด
 *   AUTH_REQUEST  ระหว่างที่ browser ไปหน้า login ของ provider (key = state)
 *   RESULT        ผล login ที่รอให้หน้าเว็บมารับครั้งเดียว (key = ค่าใน cookie)
 */
public final class OAuthEntry implements Serializable {

    public enum Kind { AUTH_REQUEST, RESULT }

    private static final long serialVersionUID = 1L;

    public final Kind kind;
    public final Instant expiresAt;

    // AUTH_REQUEST
    public final String binding;        // ต้องตรงกับ cookie ของ browser ที่เริ่ม login (กัน login CSRF)
    public final String codeVerifier;   // PKCE
    public final String nonce;

    // RESULT
    public final String status;
    public final String challengeId;
    public final HashMap<String, Object> tokens;   // มีเฉพาะ status OK (กรณีอื่น token อยู่ใน Challenge)

    OAuthEntry(Kind kind, Instant expiresAt, String binding, String codeVerifier, String nonce,
                       String status, String challengeId, Map<String, Object> tokens) {
        this.kind = kind;
        this.expiresAt = expiresAt;
        this.binding = binding;
        this.codeVerifier = codeVerifier;
        this.nonce = nonce;
        this.status = status;
        this.challengeId = challengeId;
        this.tokens = tokens == null ? null : new HashMap<>(tokens);
    }

    public static OAuthEntry authRequest(String binding, String codeVerifier, String nonce, Instant expiresAt) {
        return new OAuthEntry(Kind.AUTH_REQUEST, expiresAt, binding, codeVerifier, nonce, null, null, null);
    }

    public static OAuthEntry result(LoginFlow.LoginResult r, Instant expiresAt) {
        return new OAuthEntry(Kind.RESULT, expiresAt, null, null, null, r.status(), r.challengeId(), r.tokens());
    }
}
