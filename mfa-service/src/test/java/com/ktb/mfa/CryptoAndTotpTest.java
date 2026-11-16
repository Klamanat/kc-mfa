package com.ktb.mfa;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;

class CryptoAndTotpTest {

    private static final String KEY = Base64.getEncoder().encodeToString(new byte[32]);

    private final MfaProps props = new MfaProps(KEY, 10, Duration.ofMinutes(15), Duration.ofMinutes(10),
            List.of(), List.of(), null, null);

    @Test
    void aesGcmRoundTripAndUniqueIv() {
        SecretCrypto c = new SecretCrypto(props);
        byte[] plain = "super-secret-20-bytes".getBytes();
        String e1 = c.encrypt(plain, "brand-a|u1");
        String e2 = c.encrypt(plain, "brand-a|u1");
        assertNotEquals(e1, e2);
        assertArrayEquals(plain, c.decrypt(e1, "brand-a|u1"));
    }

    @Test
    void ciphertextCannotBeMovedToAnotherUser() {
        SecretCrypto c = new SecretCrypto(props);
        String mine = c.encrypt("attacker-secret".getBytes(), "brand-a|attacker");
        assertThrows(IllegalStateException.class, () -> c.decrypt(mine, "brand-a|victim"));
    }

    @Test
    void rejectsSameRealmNameFromTwoIssuers() {
        assertThrows(IllegalStateException.class, () -> new MfaProps(KEY, 10, Duration.ofMinutes(15),
                Duration.ofMinutes(10),
                List.of("https://kc-uat.example.com/auth/realms/brand-a", "https://kc.example.com/auth/realms/brand-a"),
                List.of(), null, null));
        assertThrows(IllegalStateException.class, () -> new MfaProps(KEY, 10, Duration.ofMinutes(15),
                Duration.ofMinutes(10), List.of("https://kc.example.com/auth"), List.of(), null, null));
    }

    @Test
    void tamperedCiphertextIsRejected() {
        SecretCrypto c = new SecretCrypto(props);
        byte[] raw = Base64.getDecoder().decode(c.encrypt("abc".getBytes(), "o"));
        raw[raw.length - 1] ^= 1;
        String bad = Base64.getEncoder().encodeToString(raw);
        assertThrows(IllegalStateException.class, () -> c.decrypt(bad, "o"));
    }

    @Test
    void totpAcceptsCurrentCodeRejectsWrongAndMalformed() {
        TotpService t = new TotpService();
        byte[] secret = t.newSecret();
        String now = t.generateNow(secret);
        assertTrue(t.match(secret, now).isPresent());
        String wrong = now.equals("000000") ? "000001" : "000000";
        assertFalse(t.match(secret, wrong).isPresent());
        assertFalse(t.match(secret, "12345").isPresent());
        assertFalse(t.match(secret, "abcdef").isPresent());
        assertFalse(t.match(secret, null).isPresent());
    }

    @Test
    void totpMatchesRfc6238Sha1Vector() throws Exception {
        // RFC 6238 Appendix B: secret "12345678901234567890", T=59s -> 94287082 (8 หลัก) => 6 หลักสุดท้าย 287082
        TotpService t = new TotpService();
        byte[] secret = "12345678901234567890".getBytes();
        java.security.Key k = new javax.crypto.spec.SecretKeySpec(secret, "HmacSHA1");
        var gen = new com.eatthepath.otp.TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(30), 6);
        assertEquals(287082, gen.generateOneTimePassword(k, java.time.Instant.ofEpochSecond(59)));
        assertTrue(t.toBase32(secret).startsWith("GEZDGNBVGY3TQOJQ"));
    }

    @Test
    void otpauthUriIsEncoded() {
        TotpService t = new TotpService();
        String uri = t.otpauthUri("Brand A", "john doe@example.com", "12345678901234567890".getBytes());
        assertTrue(uri.startsWith("otpauth://totp/Brand%20A:john%20doe%40example.com?secret="));
        assertTrue(uri.contains("&issuer=Brand%20A&"));
    }
}
