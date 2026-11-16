package com.ktb.kcmfa.starter;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * login -> (MFA_REQUIRED | ENROLL_REQUIRED | OK)
 * หลักการ: ถ้าเรียก MFA service ไม่ได้ ต้อง fail-closed (ไม่ปล่อย token) และ revoke session ที่เพิ่งเปิดที่ Keycloak
 */
public class LoginFlow {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record LoginResult(String status, String challengeId, Map<String, Object> tokens) {}

    private final KeycloakClient keycloak;
    private final MfaServiceClient mfa;
    private final ChallengeStore store;
    private final KcMfaProperties props;
    private final SessionRevoker revoker;

    public LoginFlow(KeycloakClient keycloak, MfaServiceClient mfa, ChallengeStore store, KcMfaProperties props) {
        this(keycloak, mfa, store, props, new SessionRevoker(keycloak, null));
    }

    public LoginFlow(KeycloakClient keycloak, MfaServiceClient mfa, ChallengeStore store, KcMfaProperties props,
                     SessionRevoker revoker) {
        this.revoker = revoker;
        this.keycloak = keycloak;
        this.mfa = mfa;
        this.store = store;
        this.props = props;
    }

    /** ตรวจรหัสผ่านกับ Keycloak ด้วย KeycloakClient ของ starter แล้วต่อด้วย {@link #afterPassword} */
    public LoginResult login(String username, String password) {
        Map<String, Object> tokens = keycloak.passwordGrant(username, password)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));
        return afterPassword(username, tokens);
    }

    /**
     * สำหรับเว็บที่มี wrapper เรียก Keycloak เองอยู่แล้ว: เรียกเมธอดนี้ <b>หลังรหัสผ่านผ่านแล้วเท่านั้น</b>
     * โดยส่ง token response ที่ได้จาก Keycloak (ต้องมี access_token และควรมี refresh_token ไว้ใช้ revoke)
     * ผลที่ได้เหมือน login(): OK(tokens) | MFA_REQUIRED | ENROLL_REQUIRED
     */
    public LoginResult afterPassword(String username, Map<String, Object> tokens) {
        return afterPassword(username, KeycloakClient.subjectOf(tokens), tokens);
    }

    /** เหมือนด้านบน แต่ระบุ userId (claim "sub") เองได้ ถ้าเว็บรู้อยู่แล้ว */
    public LoginResult afterPassword(String username, String userId, Map<String, Object> tokens) {
        return afterFirstFactor(username, userId, tokens, false);
    }

    /**
     * หลัง login ผ่าน OAuth provider ภายนอกสำเร็จ (ดู {@link OAuthLoginFlow})
     * userId ต้องไม่ชนกับ sub ของ Keycloak และ tokens เป็นของ provider นั้น (ไม่ถูกส่งไป Keycloak ตอน revoke)
     */
    public LoginResult afterExternalLogin(String username, String userId, Map<String, Object> tokens) {
        return afterFirstFactor(username, userId, tokens, true);
    }

    private LoginResult afterFirstFactor(String username, String userId, Map<String, Object> tokens, boolean external) {
        MfaServiceClient.Status status;
        try {
            status = mfa.status(userId, proofOf(tokens, external));
        } catch (RuntimeException e) {
            revoker.revoke(tokens, external);
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "MFA service unavailable", e);
        }

        if (status.enrolled()) {
            Challenge c = store.create(Challenge.Type.VERIFY, userId, username, tokens, props.challengeTtl(), external);
            return new LoginResult("MFA_REQUIRED", c.id, null);
        }
        if (status.enforce()) {
            Challenge c = store.create(Challenge.Type.ENROLL, userId, username, tokens, props.challengeTtl(), external);
            return new LoginResult("ENROLL_REQUIRED", c.id, null);
        }
        return new LoginResult("OK", null, tokens);
    }

    public Map<String, Object> verify(String challengeId, String code) {
        Challenge c = require(challengeId, Challenge.Type.VERIFY);
        MfaResult r = call(() -> mfa.verify(c.userId, code, proofOf(c.tokens, c.external)));
        if (r == MfaResult.OK) {
            store.remove(c.id);
            return c.tokens;
        }
        if (r == MfaResult.LOCKED) {
            discard(c);
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Account temporarily locked");
        }
        failAttempt(c);
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid code");
    }

    public MfaServiceClient.EnrollStart enrollStart(String challengeId) {
        Challenge c = require(challengeId, Challenge.Type.ENROLL);
        Optional<MfaServiceClient.EnrollStart> r = call(() -> mfa.enrollStart(c.userId, c.username, proofOf(c.tokens, c.external)));
        if (r.isEmpty()) {
            discard(c);
            throw new ResponseStatusException(HttpStatus.CONFLICT, "MFA already enrolled");
        }
        return r.get();
    }

    public Map<String, Object> enrollConfirm(String challengeId, String code) {
        Challenge c = require(challengeId, Challenge.Type.ENROLL);
        MfaResult r = call(() -> mfa.enrollConfirm(c.userId, code, proofOf(c.tokens, c.external)));
        if (r == MfaResult.OK) {
            store.remove(c.id);
            return c.tokens;
        }
        if (r == MfaResult.NO_PENDING) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Call enroll/start first");
        }
        if (r == MfaResult.ALREADY_ENROLLED) {
            discard(c);
            throw new ResponseStatusException(HttpStatus.CONFLICT, "MFA already enrolled");
        }
        failAttempt(c);
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid code");
    }

    /** token ที่ MFA service ใช้ยืนยันว่า user ผ่านปัจจัยแรกจริง: access token ของ Keycloak หรือ id_token ของ provider ภายนอก */
    private static String proofOf(Map<String, Object> tokens, boolean external) {
        Object o = tokens.get(external ? "id_token" : "access_token");
        return o == null ? null : o.toString();
    }

    private Challenge require(String id, Challenge.Type type) {
        Challenge c = store.find(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Challenge expired or invalid"));
        if (c.type != type) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Challenge expired or invalid");
        }
        if (c.expiresAt.isBefore(Instant.now())) {
            discard(c);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Challenge expired or invalid");
        }
        return c;
    }

    private void failAttempt(Challenge c) {
        if (store.incrementAttempts(c.id) >= props.maxAttempts()) {
            discard(c);
        }
    }

    /** ลบ challenge และ revoke session ที่ผู้ออก token */
    private void discard(Challenge c) {
        store.remove(c.id);
        revoker.revoke(c.tokens, c.external);
    }

    private <T> T call(Supplier<T> s) {
        try {
            return s.get();
        } catch (RuntimeException e) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "MFA service unavailable", e);
        }
    }
}
