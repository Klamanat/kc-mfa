package com.ktb.mfa;

import java.net.URL;

import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;

/**
 * ตัวตนของ backend ที่เรียก service นี้ ดึงจาก token (client_credentials) ที่ Keycloak ออกให้
 * realm มาจาก iss และ clientId มาจาก azp จึงปลอมจาก path/body ไม่ได้ และต้องเป็น token ของ service account เท่านั้น
 */
public record Caller(String realm, String clientId) {

    private static final String REALMS = "/realms/";

    public static Caller from(Jwt jwt) {
        URL iss = jwt.getIssuer();
        String azp = jwt.getClaimAsString("azp");
        if (iss == null || azp == null || azp.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Token has no issuer/azp");
        }
        if (!isServiceAccount(jwt, azp)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Not a service-account token");
        }
        String realm = realmOf(iss.toString());
        if (realm == null) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Cannot determine realm from issuer");
        }
        return new Caller(realm, azp);
    }

    /** ชื่อ realm จาก issuer URL (.../realms/{realm}) หรือ null ถ้าอ่านไม่ได้ */
    static String realmOf(String issuer) {
        int i = issuer == null ? -1 : issuer.lastIndexOf(REALMS);
        String realm = i < 0 ? "" : issuer.substring(i + REALMS.length());
        return realm.isBlank() || realm.contains("/") ? null : realm;
    }

    /**
     * รับเฉพาะ token จาก client_credentials ของ backend เอง
     * access token ของ user (password grant / authorization code) ก็มี iss และ azp ชุดเดียวกัน
     * ถ้าไม่กันไว้ user ที่ login แล้วจะเรียก service นี้แทน user คนอื่นได้
     *
     * Keycloak ใส่ claim ของ client ให้เฉพาะ token ของ service account ผ่าน mapper "Client ID"
     * (ชื่อ claim: clientId ในรุ่นเก่า, client_id ในรุ่นใหม่) token ของ user ไม่มี claim นี้
     */
    private static boolean isServiceAccount(Jwt jwt, String azp) {
        return azp.equals(jwt.getClaimAsString("client_id")) || azp.equals(jwt.getClaimAsString("clientId"));
    }
}
