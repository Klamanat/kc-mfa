package com.ktb.kcmfa.starter;

import java.time.Instant;
import java.util.Map;

/** ขอและแคช token (client_credentials) ของเว็บนี้ เพื่อใช้เรียก MFA service */
public class ServiceTokenProvider {

    private static final long SKEW_SECONDS = 30;

    private final KeycloakClient keycloak;
    private String token;
    private Instant expiresAt = Instant.EPOCH;

    public ServiceTokenProvider(KeycloakClient keycloak) {
        this.keycloak = keycloak;
    }

    public synchronized String get() {
        if (token == null || Instant.now().isAfter(expiresAt.minusSeconds(SKEW_SECONDS))) {
            Map<String, Object> m = keycloak.clientCredentials();
            token = (String) m.get("access_token");
            long ttl = m.get("expires_in") instanceof Number n ? n.longValue() : 60;
            expiresAt = Instant.now().plusSeconds(ttl);
        }
        return token;
    }
}
