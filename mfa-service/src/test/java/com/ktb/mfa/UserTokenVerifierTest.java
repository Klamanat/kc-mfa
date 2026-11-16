package com.ktb.mfa;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;

class UserTokenVerifierTest {

    private static final String KC = "https://kc.example.com/auth/realms/brand-a";
    private static final String GOOGLE = "https://accounts.google.com";

    private final Caller caller = new Caller("brand-a", "web1-backend");
    private final MfaProps.Client client = new MfaProps.Client("brand-a", "web1-backend", true, "Brand A",
            List.of("web1-frontend"),
            List.of(new MfaProps.ExternalProvider("google", GOOGLE, "google-client-id"),
                    new MfaProps.ExternalProvider("github", null, null)));

    /** token ปลอม: "issuer-ที่ออก|json-ไม่ใช้" -> ตัวถอดจำลองคืน Jwt ที่เตรียมไว้ตาม token value */
    private final Map<String, Jwt> issued = new HashMap<>();

    private final UserTokenVerifier verifier = new UserTokenVerifier(
            new MfaProps(Base64.getEncoder().encodeToString(new byte[32]), 10, Duration.ofMinutes(15),
                    Duration.ofMinutes(10), List.of(KC), List.of(), "mfa-service", Duration.ofMinutes(15)),
            (issuer, grace) -> token -> {
                Jwt jwt = issued.get(issuer + "|" + token);
                if (jwt == null) {
                    throw new BadJwtException("bad signature / wrong issuer");
                }
                return jwt;
            });

    private String token(String issuer, String value, String sub, String azp, String aud) {
        Jwt.Builder b = Jwt.withTokenValue(value).header("alg", "RS256").issuer(issuer).subject(sub);
        if (azp != null) {
            b.claim("azp", azp);
        }
        if (aud != null) {
            b.audience(List.of(aud));
        }
        issued.put(issuer + "|" + value, b.build());
        return value;
    }

    private int statusOf(String userId, String userToken) {
        return assertThrows(ResponseStatusException.class,
                () -> verifier.verify(KC, caller, client, userId, userToken)).getStatusCode().value();
    }

    @Test
    void acceptsKeycloakUsersOwnToken() {
        assertDoesNotThrow(() -> verifier.verify(KC, caller, client, "u1", token(KC, "t1", "u1", "web1-backend", null)));
        assertDoesNotThrow(() -> verifier.verify(KC, caller, client, "u1", token(KC, "t2", "u1", "web1-frontend", null)));
    }

    @Test
    void rejectsMissingOrInvalidToken() {
        assertEquals(403, statusOf("u1", null));
        assertEquals(403, statusOf("u1", " "));
        assertEquals(403, statusOf("u1", "forged"));
    }

    @Test
    void rejectsTokenOfAnotherUserOrAnotherClient() {
        assertEquals(403, statusOf("victim", token(KC, "t1", "attacker", "web1-backend", null)));
        assertEquals(403, statusOf("u1", token(KC, "t2", "u1", "other-web", null)));
        assertEquals(403, statusOf("u1", token(KC, "t3", "u1", null, null)));
    }

    @Test
    void rejectsKeycloakTokenFromAnotherIssuer() {
        // token ลงชื่อโดย issuer อื่น: ตัวถอดของ realm ผู้เรียกต้องไม่รับ
        assertEquals(403, statusOf("u1", token(GOOGLE, "t1", "u1", "web1-backend", null)));
    }

    @Test
    void acceptsExternalUserWithProvidersIdToken() {
        String userId = "google." + UserTokenVerifier.sha256("1234567890");
        assertDoesNotThrow(() -> verifier.verify(KC, caller, client, userId,
                token(GOOGLE, "id1", "1234567890", null, "google-client-id")));
    }

    @Test
    void rejectsExternalUserWithWrongSubjectAudienceOrProvider() {
        String userId = "google." + UserTokenVerifier.sha256("1234567890");
        assertEquals(403, statusOf(userId, token(GOOGLE, "id1", "someone-else", null, "google-client-id")));
        assertEquals(403, statusOf(userId, token(GOOGLE, "id2", "1234567890", null, "another-app")));
        assertEquals(403, statusOf(userId, null));
        // token ของ Keycloak ใช้แทน id_token ของ provider ไม่ได้
        assertEquals(403, statusOf(userId, token(KC, "t1", "1234567890", "web1-backend", "google-client-id")));
        // provider ที่ไม่ได้ตั้งไว้ให้ client นี้
        assertEquals(403, statusOf("azure." + UserTokenVerifier.sha256("x"), "anything"));
    }

    @Test
    void providerWithoutIssuerIsAcceptedUnverifiedByExplicitConfig() {
        assertDoesNotThrow(() -> verifier.verify(KC, caller, client, "github." + UserTokenVerifier.sha256("42"), null));
    }
}
