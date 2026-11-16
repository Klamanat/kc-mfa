package com.ktb.kcmfa.starter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Base64;

import org.junit.jupiter.api.Test;

class PayloadCipherTest {

    private static final String KEY = Base64.getEncoder().encodeToString(new byte[32]);

    @Test
    void roundTripAndRandomIv() {
        PayloadCipher c = new PayloadCipher(KEY);
        String a = c.encrypt("{\"refresh_token\":\"r1\"}", "p:ch:1");
        String b = c.encrypt("{\"refresh_token\":\"r1\"}", "p:ch:1");
        assertNotEquals(a, b);
        assertFalse(a.contains("r1"));
        assertEquals("{\"refresh_token\":\"r1\"}", c.decrypt(a, "p:ch:1"));
    }

    @Test
    void valueCannotBeMovedToAnotherKeyOrTampered() {
        PayloadCipher c = new PayloadCipher(KEY);
        String sealed = c.encrypt("secret", "p:ch:1");
        assertNull(c.decrypt(sealed, "p:ch:2"));
        assertNull(c.decrypt(sealed.substring(0, sealed.length() - 2) + "AA", "p:ch:1"));
        assertNull(c.decrypt("plain json", "p:ch:1"));
        assertNull(c.decrypt(null, "p:ch:1"));
    }

    @Test
    void rejectsBadKeys() {
        assertThrows(IllegalStateException.class, () -> new PayloadCipher(null));
        assertThrows(IllegalStateException.class, () -> new PayloadCipher("not base64 !!"));
        assertThrows(IllegalStateException.class,
                () -> new PayloadCipher(Base64.getEncoder().encodeToString(new byte[16])));
    }
}
