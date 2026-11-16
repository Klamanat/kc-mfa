package com.ktb.kcmfa.starter;

import java.io.Serializable;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/** สถานะระหว่างรอ OTP: เก็บ token ของ Keycloak ไว้ฝั่ง server (browser ได้แค่ id สุ่ม) */
public final class Challenge implements Serializable {

    public enum Type { VERIFY, ENROLL }

    private static final long serialVersionUID = 1L;

    public final String id;
    public final Type type;
    public final String userId;
    public final String username;
    public final HashMap<String, Object> tokens;
    public final Instant expiresAt;
    public final boolean external;   // true = token มาจาก OAuth provider ภายนอก (ไม่ใช่ Keycloak)

    public Challenge(String id, Type type, String userId, String username,
                     Map<String, Object> tokens, Instant expiresAt, boolean external) {
        this.id = id;
        this.type = type;
        this.userId = userId;
        this.username = username;
        this.tokens = new HashMap<>(tokens);
        this.expiresAt = expiresAt;
        this.external = external;
    }
}
