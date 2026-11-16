package com.ktb.kcmfa.starter;

import java.util.Map;

/**
 * ยกเลิก session/token ที่ค้างเมื่อ login ไม่จบ (ไม่ผ่าน MFA, challenge หมดอายุ, MFA service ล่ม)
 * token ต้องถูกส่งกลับไปยกเลิกที่ผู้ออกเท่านั้น: ของ Keycloak ไป Keycloak, ของ provider ภายนอกไป provider นั้น
 */
public class SessionRevoker {

    private final KeycloakClient keycloak;
    private final ExternalOAuthClient external;   // null ถ้าไม่ได้เปิด kcmfa.oauth

    public SessionRevoker(KeycloakClient keycloak, ExternalOAuthClient external) {
        this.keycloak = keycloak;
        this.external = external;
    }

    public void revoke(Map<String, Object> tokens, boolean fromExternalProvider) {
        if (tokens == null) {
            return;
        }
        if (fromExternalProvider) {
            if (external != null) {
                external.revoke(tokens);
            }
            return;
        }
        Object refresh = tokens.get("refresh_token");
        keycloak.logout(refresh == null ? null : refresh.toString());
    }
}
