package com.ktb.kcmfa.starter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

/**
 * Login ผ่าน OAuth 2.0 / OIDC provider ภายนอก (ไม่ใช่ Keycloak) ด้วย Authorization Code + PKCE
 * แล้วต่อด้วย MFA ของ MFA service กลางเหมือน login ด้วยรหัสผ่าน
 *
 *   start()    -> URL ไปหน้า login ของ provider + ค่าที่ต้องใส่ cookie ผูกกับ browser
 *   callback() -> แลก code เป็น token ที่ backend, ระบุตัว user, เรียก LoginFlow.afterExternalLogin
 *   result()   -> หน้าเว็บมารับผล (OK | MFA_REQUIRED | ENROLL_REQUIRED) ครั้งเดียว
 *
 * token และ challengeId ไม่ผ่าน URL เลย: callback เก็บผลไว้ฝั่ง server แล้วให้หน้าเว็บมารับด้วย cookie httpOnly
 *
 * userId ที่ส่งให้ MFA service = "{provider}.{base64url(SHA-256(sub))}" จึงไม่ชนกับ sub ของ Keycloak
 * และไม่ชนกันระหว่าง provider (MFA ของบัญชี Keycloak กับบัญชี provider ภายนอกเป็นคนละชุดกัน)
 */
public class OAuthLoginFlow {

    public record Start(String authorizationUrl, String cookieValue) {}

    private static final String STATE = "s:";
    private static final String RESULT = "r:";

    private final ExternalOAuthClient oauth;
    private final LoginFlow loginFlow;
    private final OAuthStateStore store;
    private final KcMfaProperties.OAuth cfg;
    private final SecureRandom random = new SecureRandom();

    public OAuthLoginFlow(ExternalOAuthClient oauth, LoginFlow loginFlow, OAuthStateStore store, KcMfaProperties props) {
        this.oauth = oauth;
        this.loginFlow = loginFlow;
        this.store = store;
        this.cfg = props.oauth();
        require(cfg.provider() != null && cfg.provider().matches("[a-z0-9-]{1,16}"),
                "kcmfa.oauth.provider must match [a-z0-9-]{1,16}");
        require(notBlank(cfg.authorizationUri()), "kcmfa.oauth.authorization-uri is required");
        require(notBlank(cfg.tokenUri()), "kcmfa.oauth.token-uri is required");
        require(notBlank(cfg.clientId()), "kcmfa.oauth.client-id is required");
        require(notBlank(cfg.redirectUri()), "kcmfa.oauth.redirect-uri is required");
    }

    public Start start() {
        String state = token();
        String binding = token();
        String verifier = token();   // 43 ตัวอักษร base64url ตาม RFC 7636
        String nonce = token();
        store.put(STATE + state, OAuthEntry.authRequest(binding, verifier, nonce, Instant.now().plus(cfg.stateTtl())));
        return new Start(oauth.authorizationUrl(state, nonce, s256(verifier)), binding);
    }

    /**
     * @param cookieValue ค่า cookie ที่ตั้งไว้ตอน start()
     * @return ค่าที่ต้องใส่ cookie ใหม่ เพื่อให้หน้าเว็บเรียก result()
     */
    public String callback(String code, String state, String cookieValue) {
        OAuthEntry req = state == null ? null : store.take(STATE + state).orElse(null);
        if (req == null || req.kind != OAuthEntry.Kind.AUTH_REQUEST || req.expiresAt.isBefore(Instant.now())
                || !same(req.binding, cookieValue)
                || code == null || code.isBlank()) {
            throw unauthorized();
        }

        Map<String, Object> tokens = oauth.authorizationCodeGrant(code, req.codeVerifier)
                .orElseThrow(OAuthLoginFlow::unauthorized);

        String subject;
        String username;
        try {
            Map<String, Object> claims = claims(tokens, req.nonce);
            subject = str(claims.get(cfg.userIdClaim()));
            if (!notBlank(subject)) {
                throw unauthorized();
            }
            username = firstNonBlank(str(claims.get(cfg.usernameClaim())),
                    str(claims.get("preferred_username")), str(claims.get("email")), subject);
        } catch (RuntimeException e) {
            oauth.revoke(tokens);
            throw unauthorized();
        }

        // fail-closed + revoke เมื่อ MFA service ล่ม ทำใน LoginFlow อยู่แล้ว
        LoginFlow.LoginResult result = loginFlow.afterExternalLogin(username, userIdOf(subject), tokens);

        String handle = token();
        store.put(RESULT + handle, OAuthEntry.result(result, Instant.now().plus(cfg.resultTtl())));
        return handle;
    }

    /** หน้าเว็บมารับผล login (ใช้ได้ครั้งเดียว) รูปแบบเดียวกับ LoginFlow.login() */
    public LoginFlow.LoginResult result(String cookieValue) {
        OAuthEntry e = cookieValue == null ? null : store.take(RESULT + cookieValue).orElse(null);
        if (e == null || e.kind != OAuthEntry.Kind.RESULT) {
            throw unauthorized();
        }
        if (e.expiresAt.isBefore(Instant.now())) {
            oauth.revoke(e.tokens);
            throw unauthorized();
        }
        return new LoginFlow.LoginResult(e.status, e.challengeId, e.tokens);
    }

    /** revoke token ของผล login ที่ไม่มีใครมารับจนหมดอายุ (ChallengeSweeper เรียกเป็นรอบ) */
    public void sweepExpired() {
        store.removeExpired().forEach(e -> oauth.revoke(e.tokens));
    }

    /** userId ที่ใช้กับ MFA service: คงที่ต่อ (provider, sub) และอยู่ในรูปแบบที่ service รับ ([A-Za-z0-9._-]{1,64}) */
    String userIdOf(String subject) {
        return cfg.provider() + "." + sha256(subject.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * ข้อมูล user: จาก id_token ถ้ามี (ตรวจ nonce และ aud) ไม่งั้นจาก userinfo endpoint
     * id_token ได้จาก token endpoint โดยตรงผ่าน TLS จึงไม่ต้อง verify signature (OIDC Core 3.1.3.7)
     */
    private Map<String, Object> claims(Map<String, Object> tokens, String nonce) {
        String idToken = str(tokens.get("id_token"));
        if (idToken == null) {
            return oauth.userInfo(str(tokens.get("access_token")));
        }
        Map<String, Object> claims = ExternalOAuthClient.jwtClaims(idToken);
        if (!same(nonce, str(claims.get("nonce"))) || !audienceIsUs(claims.get("aud"))) {
            throw unauthorized();
        }
        return claims;
    }

    private boolean audienceIsUs(Object aud) {
        if (aud instanceof Collection<?> c) {
            return c.contains(cfg.clientId());
        }
        return cfg.clientId().equals(aud);
    }

    private String token() {
        byte[] b = new byte[32];
        random.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    static String s256(String verifier) {
        return sha256(verifier.getBytes(StandardCharsets.US_ASCII));
    }

    private static String sha256(byte[] in) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(in));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static boolean same(String a, String b) {
        return a != null && b != null
                && MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private static String firstNonBlank(String... values) {
        for (String v : values) {
            if (notBlank(v)) {
                return v;
            }
        }
        return null;
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }

    private static String str(Object o) {
        return o == null ? null : o.toString();
    }

    private static void require(boolean ok, String message) {
        if (!ok) {
            throw new IllegalStateException(message + " (kcmfa.oauth.enabled=true)");
        }
    }

    private static ResponseStatusException unauthorized() {
        return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "OAuth login expired or invalid");
    }
}
