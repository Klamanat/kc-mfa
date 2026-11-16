package com.ktb.kcmfa.starter;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * kcmfa.keycloak.*     Keycloak ของ realm ตัวเอง (client ของเว็บนี้: confidential, Direct Access Grants + Service Accounts เปิด)
 * kcmfa.mfa-service.*  URL ของ MFA service กลาง
 * kcmfa.store          memory (ค่าเริ่มต้น, instance เดียว) | redis (หลาย instance ต้องมี spring-boot-starter-data-redis)
 * kcmfa.redis-encryption-key   จำเป็นเมื่อ store=redis: คีย์ AES-256 (base64 32 bytes) เข้ารหัส token ที่เก็บใน Redis
 * kcmfa.redis-allow-plaintext  true = ยอมเก็บเป็นข้อความล้วน (ไม่แนะนำ ใช้เฉพาะ Redis ที่เป็นของเว็บนี้ทั้งหมด + TLS + ACL)
 */
@ConfigurationProperties(prefix = "kcmfa")
public record KcMfaProperties(Keycloak keycloak,
                              MfaService mfaService,
                              @DefaultValue("5m") Duration challengeTtl,
                              @DefaultValue("5") int maxAttempts,
                              @DefaultValue("2s") Duration connectTimeout,
                              @DefaultValue("5s") Duration readTimeout,
                              @DefaultValue("30s") Duration sweepInterval,
                              @DefaultValue OAuth oauth,
                              @DefaultValue("memory") String store,
                              String redisKeyPrefix,
                              String redisEncryptionKey,
                              @DefaultValue("false") boolean redisAllowPlaintext) {

    /**
     * prefix ของ key ใน Redis (kcmfa.store=redis) ต้องไม่ซ้ำกันระหว่างเว็บที่ใช้ Redis ร่วมกัน
     * ไม่งั้นตัวเก็บกวาดของเว็บหนึ่งจะไปหยิบ challenge ของอีกเว็บ ค่าเริ่มต้น = kcmfa:{client-id}:
     */
    public String redisPrefix() {
        return redisKeyPrefix != null && !redisKeyPrefix.isBlank()
                ? redisKeyPrefix
                : "kcmfa:" + keycloak.clientId() + ":";
    }

    /**
     * kcmfa.oauth.*  login ผ่าน OAuth 2.0 / OIDC provider ภายนอก (ไม่ใช่ Keycloak) ด้วย Authorization Code + PKCE
     * provider          ชื่อสั้นของ provider [a-z0-9-]{1,16} ใช้เป็น namespace ของ userId ที่ส่งให้ MFA service
     * user-info-uri     จำเป็นเมื่อ provider ไม่ออก id_token (OAuth2 ล้วน เช่น GitHub)
     * revocation-uri    ตัวเลือก (RFC 7009) ใช้ยกเลิก token เมื่อไม่ผ่าน MFA
     * client-auth       post = client_secret ใน form, basic = HTTP Basic
     * redirect-uri      URL เต็มของ {base-path}/oauth/callback ที่ browser เห็น (ต้องตรงกับที่ลงทะเบียนไว้กับ provider เป๊ะ)
     * success-redirect  หน้าเว็บที่จะเรียก POST {base-path}/oauth/result ต่อ
     * failure-redirect  หน้าเว็บเมื่อ login ไม่สำเร็จ (ต่อท้ายด้วย ?error=oauth_failed | mfa_unavailable)
     */
    public record OAuth(@DefaultValue("false") boolean enabled,
                        String provider,
                        String authorizationUri,
                        String tokenUri,
                        String userInfoUri,
                        String revocationUri,
                        String clientId,
                        String clientSecret,
                        @DefaultValue("post") String clientAuth,
                        String redirectUri,
                        @DefaultValue("openid") String scope,
                        @DefaultValue("sub") String userIdClaim,
                        @DefaultValue("email") String usernameClaim,
                        @DefaultValue("/") String successRedirect,
                        @DefaultValue("/login") String failureRedirect,
                        @DefaultValue("5m") Duration stateTtl,
                        @DefaultValue("1m") Duration resultTtl,
                        @DefaultValue("true") boolean cookieSecure,
                        @DefaultValue("/") String cookiePath) {}

    public record Keycloak(String baseUrl, String realm, String clientId, String clientSecret) {
        public String tokenUrl() {
            return baseUrl + "/realms/" + realm + "/protocol/openid-connect/token";
        }

        public String logoutUrl() {
            return baseUrl + "/realms/" + realm + "/protocol/openid-connect/logout";
        }
    }

    public record MfaService(String url) {}
}
