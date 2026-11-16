package com.ktb.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;

class CallerTest {

    /** token ของ service account: มี claim ของ client (ชื่อ claim ต่างกันตามรุ่น Keycloak) */
    private static Jwt jwt(String iss, String azp, String clientClaim) {
        Jwt.Builder b = Jwt.withTokenValue("t").header("alg", "none").claim("sub", "svc").issuer(iss);
        if (azp != null) {
            b.claim("azp", azp);
            if (clientClaim != null) {
                b.claim(clientClaim, azp);
            }
        }
        return b.build();
    }

    private static Jwt jwt(String iss, String azp) {
        return jwt(iss, azp, "client_id");
    }

    @Test
    void readsRealmFromIssuerAndClientFromAzp() {
        Caller c = Caller.from(jwt("https://kc.example.com/auth/realms/brand-a", "web1-backend"));
        assertEquals("brand-a", c.realm());
        assertEquals("web1-backend", c.clientId());
    }

    @Test
    void worksWithoutAuthPrefixToo() {
        assertEquals("brand-b", Caller.from(jwt("https://kc.example.com/realms/brand-b", "x")).realm());
    }

    @Test
    void acceptsOlderKeycloakClaimName() {
        assertEquals("x", Caller.from(jwt("https://kc.example.com/auth/realms/a", "x", "clientId")).clientId());
    }

    @Test
    void rejectsMissingAzpOrBadIssuer() {
        assertThrows(ResponseStatusException.class, () -> Caller.from(jwt("https://kc.example.com/auth/realms/a", null)));
        assertThrows(ResponseStatusException.class, () -> Caller.from(jwt("https://kc.example.com/auth", "x")));
    }

    @Test
    void rejectsUserTokenOfTheSameClient() {
        // access token ของ user ที่ login ผ่านเว็บ: iss/azp ถูกต้อง แต่ไม่มี claim ของ service account
        assertThrows(ResponseStatusException.class,
                () -> Caller.from(jwt("https://kc.example.com/auth/realms/a", "web1-backend", null)));
        // claim ของ client อื่นก็ใช้ไม่ได้
        Jwt other = Jwt.withTokenValue("t").header("alg", "none").claim("sub", "svc")
                .issuer("https://kc.example.com/auth/realms/a")
                .claim("azp", "web1-backend").claim("client_id", "another").build();
        assertThrows(ResponseStatusException.class, () -> Caller.from(other));
    }
}
