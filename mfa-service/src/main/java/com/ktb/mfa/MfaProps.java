package com.ktb.mfa;

import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "mfa")
public record MfaProps(String encryptionKey,
                       int lockAfterFailures,
                       Duration lockDuration,
                       Duration enrollTtl,
                       List<String> trustedIssuers,
                       List<Client> clients,
                       String requiredAudience,
                       Duration userTokenGrace) {

    /**
     * MFA ของ user ใช้ key (ชื่อ realm, userId) ชื่อ realm จึงต้องไม่ซ้ำกันระหว่าง issuer ที่เชื่อถือ
     * ไม่งั้น backend ของ Keycloak ตัวหนึ่ง (เช่น UAT) จะจัดการ MFA ของ user ใน realm ชื่อเดียวกันของอีกตัว (PROD) ได้
     */
    public MfaProps {
        trustedIssuers = trustedIssuers == null ? List.of() : List.copyOf(trustedIssuers);
        clients = clients == null ? List.of() : List.copyOf(clients);
        Set<String> realms = new HashSet<>();
        for (String issuer : trustedIssuers) {
            String realm = Caller.realmOf(issuer);
            if (realm == null) {
                throw new IllegalStateException("mfa.trusted-issuers: cannot read realm from " + issuer);
            }
            if (!realms.add(realm)) {
                throw new IllegalStateException("mfa.trusted-issuers: realm name \"" + realm
                        + "\" appears in more than one issuer; run a separate mfa-service per Keycloak");
            }
        }
    }

    /**
     * backend ที่อนุญาตให้เรียก service นี้ พร้อม policy ของเว็บนั้น
     * @param loginClientIds    client อื่นของ realm เดียวกันที่ออก token ให้ user ของเว็บนี้ (ถ้า login ไม่ได้ใช้ client-id ตัวเดียวกับ backend)
     * @param externalProviders OAuth provider ภายนอกที่เว็บนี้ใช้ login ได้ (ดู UserTokenVerifier)
     * @param inviteRequired    ลงทะเบียน MFA ครั้งแรกต้องมีรหัสเชิญที่ admin ออกให้ (กันคนที่รู้แค่รหัสผ่านมา enroll ก่อนเจ้าของ)
     *                          ไม่ตั้ง = ตาม enforce (เว็บที่บังคับ MFA ต้องใช้รหัสเชิญโดยปริยาย) ตั้ง false เองเท่านั้นจึงจะปิด
     * @param admin             true = client นี้ (service account ของเครื่องมือ admin) ออกรหัสเชิญ / reset MFA ได้
     */
    public record Client(String realm, String clientId, boolean enforce, String issuerLabel,
                         List<String> loginClientIds, List<ExternalProvider> externalProviders,
                         Boolean inviteRequired, boolean admin) {

        /** ค่าที่ใช้จริง: ตั้งไว้ใช้ตามนั้น ไม่ตั้งใช้ตาม enforce */
        public boolean requiresInvite() {
            return inviteRequired != null ? inviteRequired : enforce;
        }

        public Optional<ExternalProvider> externalProvider(String provider) {
            return externalProviders == null ? Optional.empty()
                    : externalProviders.stream().filter(p -> provider.equals(p.provider())).findFirst();
        }
    }

    /**
     * @param provider ค่าเดียวกับ kcmfa.oauth.provider ของเว็บ
     * @param issuer   iss ของ id_token (ต้องมี OIDC discovery) เว้นว่าง = provider ไม่ออก id_token ยอมรับโดยไม่มีหลักฐาน
     * @param audience client-id ที่เว็บลงทะเบียนกับ provider (aud ของ id_token)
     */
    public record ExternalProvider(String provider, String issuer, String audience) {}

    public Optional<Client> findClient(String realm, String clientId) {
        return clients.stream()
                .filter(c -> c.realm().equals(realm) && c.clientId().equals(clientId))
                .findFirst();
    }
}
