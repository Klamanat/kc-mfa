package com.ktb.mfa;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;

/**
 * เข้ารหัส TOTP secret ด้วย AES-256-GCM ก่อนลง DB (รูปแบบ: base64(iv || ciphertext+tag))
 * owner (realm|userId) ถูกผูกเป็น AAD: ciphertext ของ user หนึ่งคัดลอกไปใส่แถวของอีก user แล้วถอดไม่ออก
 */
@Component
public class SecretCrypto {

    private static final int IV_LEN = 12;
    private static final int TAG_BITS = 128;

    private final SecretKey key;
    private final SecureRandom random = new SecureRandom();

    public SecretCrypto(MfaProps props) {
        byte[] k = Base64.getDecoder().decode(props.encryptionKey());
        if (k.length != 32) {
            throw new IllegalStateException("mfa.encryption-key must be 32 bytes (base64 of AES-256 key)");
        }
        this.key = new SecretKeySpec(k, "AES");
    }

    public String encrypt(byte[] plain, String owner) {
        try {
            byte[] iv = new byte[IV_LEN];
            random.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            c.updateAAD(owner.getBytes(StandardCharsets.UTF_8));
            byte[] ct = c.doFinal(plain);
            byte[] out = new byte[IV_LEN + ct.length];
            System.arraycopy(iv, 0, out, 0, IV_LEN);
            System.arraycopy(ct, 0, out, IV_LEN, ct.length);
            return Base64.getEncoder().encodeToString(out);
        } catch (Exception e) {
            throw new IllegalStateException("encrypt failed", e);
        }
    }

    public byte[] decrypt(String encoded, String owner) {
        try {
            byte[] in = Base64.getDecoder().decode(encoded);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, in, 0, IV_LEN));
            c.updateAAD(owner.getBytes(StandardCharsets.UTF_8));
            return c.doFinal(in, IV_LEN, in.length - IV_LEN);
        } catch (Exception e) {
            throw new IllegalStateException("decrypt failed", e);
        }
    }
}
