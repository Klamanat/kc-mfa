package com.ktb.mfa;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.OptionalLong;

import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.springframework.stereotype.Component;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;

/** TOTP RFC 6238: SHA-1, 6 หลัก, 30 วินาที (เข้ากันได้กับ Google/Microsoft Authenticator) */
@Component
public class TotpService {

    private static final Duration STEP = Duration.ofSeconds(30);
    private static final int DIGITS = 6;
    private static final int WINDOW = 1; // ยอมคลาดเคลื่อน ±1 step

    private final TimeBasedOneTimePasswordGenerator gen = new TimeBasedOneTimePasswordGenerator(STEP, DIGITS);
    private final SecureRandom random = new SecureRandom();

    /** สร้าง secret ใหม่ 160 บิต */
    public byte[] newSecret() {
        byte[] s = new byte[20];
        random.nextBytes(s);
        return s;
    }

    public String toBase32(byte[] secret) {
        return new Base32().encodeToString(secret).replace("=", "");
    }

    /** URI สำหรับสร้าง QR code ฝั่ง frontend */
    public String otpauthUri(String issuerLabel, String accountName, byte[] secret) {
        String issuer = enc(issuerLabel);
        return "otpauth://totp/" + issuer + ":" + enc(accountName)
                + "?secret=" + toBase32(secret)
                + "&issuer=" + issuer
                + "&algorithm=SHA1&digits=" + DIGITS
                + "&period=" + STEP.toSeconds();
    }

    /**
     * ตรวจโค้ด
     * @return time-step ที่ตรง หรือ empty ถ้าไม่ตรง (ใช้ step นี้กัน replay)
     */
    public OptionalLong match(byte[] secret, String code) {
        if (code == null || !code.matches("\\d{" + DIGITS + "}")) {
            return OptionalLong.empty();
        }
        Key key = new SecretKeySpec(secret, gen.getAlgorithm());
        Instant now = Instant.now();
        OptionalLong found = OptionalLong.empty();
        // วนครบทุก offset เสมอ เพื่อไม่ให้เวลาตอบสนองบอกใบ้ว่าตรงช่วงไหน
        for (int off = -WINDOW; off <= WINDOW; off++) {
            Instant t = now.plus(STEP.multipliedBy(off));
            String expected = String.format("%0" + DIGITS + "d", generate(key, t));
            if (MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), code.getBytes(StandardCharsets.UTF_8))) {
                found = OptionalLong.of(t.getEpochSecond() / STEP.toSeconds());
            }
        }
        return found;
    }

    /** ใช้ในเทสต์ */
    String generateNow(byte[] secret) {
        return String.format("%0" + DIGITS + "d", generate(new SecretKeySpec(secret, gen.getAlgorithm()), Instant.now()));
    }

    private int generate(Key key, Instant t) {
        try {
            return gen.generateOneTimePassword(key, t);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
