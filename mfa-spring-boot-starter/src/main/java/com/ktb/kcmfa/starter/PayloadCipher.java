package com.ktb.kcmfa.starter;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * เข้ารหัสค่าที่เก็บใน Redis (AES-256-GCM) เพื่อไม่ให้ token ของ user อ่านได้จาก Redis โดยตรง
 * AAD = key ของ Redis: ย้ายค่าไปสวมใต้ key อื่นไม่ได้ และถ้าถูกแก้ไขจะถอดไม่ได้ (decrypt คืน null)
 * รูปแบบ: "v1." + base64url(iv[12] + ciphertext+tag)  คีย์ 32 bytes แบบ base64 (openssl rand -base64 32)
 * ยังไม่รองรับการหมุนคีย์: เปลี่ยนคีย์แล้ว challenge ที่ค้างอยู่ (อายุไม่เกินไม่กี่นาที) จะใช้ไม่ได้ ให้ user login ใหม่
 */
public final class PayloadCipher {

    private static final String PREFIX = "v1.";
    private static final int IV_LENGTH = 12;

    private final SecretKeySpec key;
    private final SecureRandom random = new SecureRandom();

    public PayloadCipher(String base64Key) {
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(base64Key == null ? "" : base64Key.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("kcmfa.redis-encryption-key must be base64", e);
        }
        if (raw.length != 32) {
            throw new IllegalStateException("kcmfa.redis-encryption-key must be 32 bytes (base64), got " + raw.length);
        }
        this.key = new SecretKeySpec(raw, "AES");
    }

    public String encrypt(String plain, String aad) {
        try {
            byte[] iv = new byte[IV_LENGTH];
            random.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            c.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
            byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
            byte[] out = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            return PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(out);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Cannot encrypt payload", e);
        }
    }

    /** @return null ถ้าไม่ใช่ค่าที่เข้ารหัสด้วยคีย์นี้/key นี้ (ถูกแก้ ถูกย้าย หรือคีย์เปลี่ยน) */
    public String decrypt(String stored, String aad) {
        if (stored == null || !stored.startsWith(PREFIX)) {
            return null;
        }
        try {
            byte[] in = Base64.getUrlDecoder().decode(stored.substring(PREFIX.length()));
            if (in.length <= IV_LENGTH) {
                return null;
            }
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, in, 0, IV_LENGTH));
            c.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
            return new String(c.doFinal(in, IV_LENGTH, in.length - IV_LENGTH), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return null;
        }
    }
}
