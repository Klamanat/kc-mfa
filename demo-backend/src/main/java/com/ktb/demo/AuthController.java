package com.ktb.demo;

import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.function.Supplier;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.ktb.kcmfa.starter.LoginFlow;
import com.ktb.kcmfa.starter.MfaServiceClient;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * login + MFA ของ demo (แทน controller ของ starter ที่ปิดด้วย kcmfa.controller.enabled=false)
 * ต่างจากของ starter:
 *   1. access token ไม่ถูกส่งกลับใน JSON แต่ตั้งเป็น cookie httpOnly + SameSite=Strict (JS อ่านไม่ได้)
 *   2. challengeId ก็อยู่ใน cookie httpOnly เช่นกัน (path /api/auth) ไม่ผ่าน JS / ไม่อยู่ใน body จึงรั่วทาง XSS หรือ log ของหน้าเว็บไม่ได้
 *   3. จำกัดจำนวนครั้งต่อ IP และต่อชื่อผู้ใช้ที่ login / ใส่รหัส OTP
 *   4. refresh_token ไม่ถูกส่งให้ browser เลย
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    public static final String COOKIE = "demo_access";
    static final String CHALLENGE_COOKIE = "demo_chal";
    private static final String CHALLENGE_GONE = "Challenge expired or invalid";   // ข้อความจาก LoginFlow.require

    public record LoginRequest(@NotBlank @Size(max = 256) String username,
                               @NotBlank @Size(max = 1024) String password) {}
    public record CodeRequest(@NotBlank @Size(max = 16) String code) {}
    public record EnrollStartRequest(@Size(max = 32) String inviteCode) {}

    private final LoginFlow flow;
    private final RateLimiter limiter;
    private final boolean cookieSecure;
    private final Duration challengeTtl;

    public AuthController(LoginFlow flow, RateLimiter limiter, DemoProperties props,
                          com.ktb.kcmfa.starter.KcMfaProperties kcmfa) {
        this.flow = flow;
        this.limiter = limiter;
        this.cookieSecure = props.cookieSecure();
        this.challengeTtl = kcmfa.challengeTtl();
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@Valid @RequestBody LoginRequest req, HttpServletRequest http) {
        // นับทั้งต่อ IP และต่อชื่อผู้ใช้: ยิงจากหลาย IP (หรือปลอม X-Forwarded-For) ใส่บัญชีเดียวกันก็ยังโดนจำกัด
        limit(http, "login");
        limitKey("login-user:" + req.username().trim().toLowerCase(Locale.ROOT));
        LoginFlow.LoginResult r = flow.login(req.username(), req.password());
        if (r.tokens() != null) {                       // ผู้ใช้ยังไม่มี MFA และ enforce=false
            return session(r.tokens());
        }
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, challengeCookie(r.challengeId(), challengeTtl).toString())
                .body(Map.of("status", r.status()));
    }

    @PostMapping("/mfa/verify")
    public ResponseEntity<Map<String, Object>> verify(@Valid @RequestBody CodeRequest req, HttpServletRequest http,
                                                      @CookieValue(name = CHALLENGE_COOKIE, required = false) String challenge) {
        limit(http, "otp");
        return session(challenged(() -> flow.verify(required(challenge), req.code())));
    }

    @PostMapping("/mfa/enroll/start")
    public MfaServiceClient.EnrollStart enrollStart(@Valid @RequestBody EnrollStartRequest req, HttpServletRequest http,
                                                    @CookieValue(name = CHALLENGE_COOKIE, required = false) String challenge) {
        limit(http, "otp");
        return challenged(() -> flow.enrollStart(required(challenge), req.inviteCode()));
    }

    @PostMapping("/mfa/enroll/confirm")
    public ResponseEntity<Map<String, Object>> enrollConfirm(@Valid @RequestBody CodeRequest req, HttpServletRequest http,
                                                             @CookieValue(name = CHALLENGE_COOKIE, required = false) String challenge) {
        limit(http, "otp");
        return session(challenged(() -> flow.enrollConfirm(required(challenge), req.code())));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout() {
        // demo ไม่เก็บ refresh_token จึง clear cookie ได้อย่างเดียว (access token ที่ออกไปแล้วยังใช้ได้จนหมดอายุ)
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, accessCookie("", Duration.ZERO).toString())
                .header(HttpHeaders.SET_COOKIE, challengeCookie("", Duration.ZERO).toString())
                .build();
    }

    private ResponseEntity<Map<String, Object>> session(Map<String, Object> tokens) {
        Object token = tokens.get("access_token");
        if (!(token instanceof String access) || access.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "No access token");
        }
        long seconds = tokens.get("expires_in") instanceof Number n ? n.longValue() : 300;
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, accessCookie(access, Duration.ofSeconds(seconds)).toString())
                .header(HttpHeaders.SET_COOKIE, challengeCookie("", Duration.ZERO).toString())
                .body(Map.of("status", "OK"));
    }

    private static String required(String challenge) {
        if (challenge == null || challenge.isBlank()) {
            throw new ResponseStatusException(HttpStatus.GONE, CHALLENGE_GONE);
        }
        return challenge;
    }

    /** challenge หมดอายุ/ไม่ถูกต้องให้ตอบ 410 (แยกจาก 401 "รหัสผิด") เพื่อให้หน้าเว็บเริ่ม login ใหม่ */
    private static <T> T challenged(Supplier<T> call) {
        try {
            return call.get();
        } catch (ResponseStatusException e) {
            if (e.getStatusCode().value() == 401 && CHALLENGE_GONE.equals(e.getReason())) {
                throw new ResponseStatusException(HttpStatus.GONE, CHALLENGE_GONE, e);
            }
            throw e;
        }
    }

    private ResponseCookie accessCookie(String value, Duration maxAge) {
        return ResponseCookie.from(COOKIE, value)
                .httpOnly(true).secure(cookieSecure).sameSite("Strict").path("/").maxAge(maxAge).build();
    }

    private ResponseCookie challengeCookie(String value, Duration maxAge) {
        return ResponseCookie.from(CHALLENGE_COOKIE, value)
                .httpOnly(true).secure(cookieSecure).sameSite("Strict").path("/api/auth").maxAge(maxAge).build();
    }

    private void limit(HttpServletRequest http, String bucket) {
        // หลัง reverse proxy ให้ตั้ง server.forward-headers-strategy ไม่งั้น remoteAddr จะเป็น IP ของ proxy ทุกคน
        limitKey(bucket + ":" + http.getRemoteAddr());
    }

    private void limitKey(String key) {
        if (!limiter.tryAcquire(key.length() > 200 ? key.substring(0, 200) : key)) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Too many requests");
        }
    }
}
