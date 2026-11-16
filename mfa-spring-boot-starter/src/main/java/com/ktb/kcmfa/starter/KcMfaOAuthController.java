package com.ktb.kcmfa.starter;

import java.net.URI;
import java.time.Duration;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Endpoint ของ login ผ่าน OAuth provider ภายนอก (เปิดด้วย kcmfa.oauth.enabled=true)
 *   GET  oauth/login      -> 302 ไปหน้า login ของ provider
 *   GET  oauth/callback   -> provider redirect กลับมา (ต้องตรงกับ kcmfa.oauth.redirect-uri) แล้ว 302 ไปหน้าเว็บ
 *   POST oauth/result     -> หน้าเว็บรับผล {status, challengeId | tokens} แล้วเดินต่อด้วย mfa/verify, mfa/enroll/* เดิม
 */
@RestController
@RequestMapping("${kcmfa.base-path:/api/auth}/oauth")
public class KcMfaOAuthController {

    /**
     * prefix __Host- ทำให้ browser รับ cookie นี้เฉพาะจาก host นี้ผ่าน HTTPS เท่านั้น (ต้อง Secure, Path=/ และไม่มี Domain)
     * subdomain อื่นหรือ HTTP จึงฝัง cookie นี้ให้เหยื่อเพื่อทำ login CSRF ไม่ได้
     * ใช้ชื่อธรรมดาเฉพาะเมื่อ cookie-secure=false หรือ cookie-path ไม่ใช่ / (เช่น dev บน http) ซึ่ง browser ไม่รับ prefix นี้
     */
    static final String HOST_COOKIE = "__Host-kcmfa_oauth";
    static final String PLAIN_COOKIE = "kcmfa_oauth";

    private final OAuthLoginFlow flow;
    private final KcMfaProperties.OAuth cfg;
    private final boolean hostPrefix;

    public KcMfaOAuthController(OAuthLoginFlow flow, KcMfaProperties props) {
        this.flow = flow;
        this.cfg = props.oauth();
        this.hostPrefix = cfg.cookieSecure() && "/".equals(cfg.cookiePath());
    }

    @GetMapping("/login")
    public ResponseEntity<Void> login() {
        OAuthLoginFlow.Start s = flow.start();
        return redirect(s.authorizationUrl(), cookie(s.cookieValue(), cfg.stateTtl()));
    }

    @GetMapping("/callback")
    public ResponseEntity<Void> callback(@RequestParam(required = false) String code,
                                         @RequestParam(required = false) String state,
                                         @CookieValue(name = HOST_COOKIE, required = false) String hostCookie,
                                         @CookieValue(name = PLAIN_COOKIE, required = false) String plainCookie) {
        String cookie = hostPrefix ? hostCookie : plainCookie;
        try {
            String handle = flow.callback(code, state, cookie);
            return redirect(cfg.successRedirect(), cookie(handle, cfg.resultTtl()));
        } catch (RuntimeException e) {
            boolean mfaDown = e instanceof ResponseStatusException r
                    && r.getStatusCode().value() == HttpStatus.SERVICE_UNAVAILABLE.value();
            String target = cfg.failureRedirect();
            target += (target.contains("?") ? "&" : "?") + "error=" + (mfaDown ? "mfa_unavailable" : "oauth_failed");
            return redirect(target, cookie("", Duration.ZERO));
        }
    }

    @PostMapping("/result")
    public ResponseEntity<LoginFlow.LoginResult> result(
            @CookieValue(name = HOST_COOKIE, required = false) String hostCookie,
            @CookieValue(name = PLAIN_COOKIE, required = false) String plainCookie) {
        LoginFlow.LoginResult r = flow.result(hostPrefix ? hostCookie : plainCookie);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie("", Duration.ZERO).toString())
                .cacheControl(CacheControl.noStore())
                .body(r);
    }

    private static ResponseEntity<Void> redirect(String url, ResponseCookie cookie) {
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(url))
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .cacheControl(CacheControl.noStore())
                .build();
    }

    /** SameSite=Lax: cookie ต้องถูกส่งมากับ redirect (top-level GET) จาก provider แต่ไม่ส่งกับ POST ข้ามเว็บ */
    private ResponseCookie cookie(String value, Duration maxAge) {
        return ResponseCookie.from(hostPrefix ? HOST_COOKIE : PLAIN_COOKIE, value)
                .httpOnly(true)
                .secure(cfg.cookieSecure())
                .sameSite("Lax")
                .path(cfg.cookiePath())
                .maxAge(maxAge)
                .build();
    }
}
