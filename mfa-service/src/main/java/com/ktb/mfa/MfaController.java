package com.ktb.mfa;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * realm ถูกกำหนดจาก token ของผู้เรียกเสมอ (ไม่รับจาก path/body)
 * backend ของ realm A จึงจัดการ MFA ของ user ใน realm B ไม่ได้
 * และทุก request ต้องแนบ token ของ user คนนั้น (X-User-Token) เป็นหลักฐานว่าผ่านปัจจัยแรกจริง
 */
@RestController
@RequestMapping("/v1/users/{userId}/mfa")
public class MfaController {

    public record StatusResponse(boolean enrolled, boolean enforce, boolean inviteRequired) {}
    public record CodeRequest(@NotBlank @Size(max = 16) String code) {}
    public record EnrollStartRequest(@NotBlank @Size(max = 256) String accountName,
                                     @Size(max = 32) String inviteCode) {}
    public record InviteResponse(String code, java.time.Instant expiresAt) {}
    public record ResultResponse(MfaService.Result result) {}
    public record EnrollStartResponse(String secret, String otpauthUri) {}

    private final MfaService mfa;
    private final MfaProps props;
    private final UserTokenVerifier userTokens;
    private final AdminGuard adminGuard;
    private final AuditService audit;

    public MfaController(MfaService mfa, MfaProps props, UserTokenVerifier userTokens,
                         AdminGuard adminGuard, AuditService audit) {
        this.mfa = mfa;
        this.props = props;
        this.userTokens = userTokens;
        this.adminGuard = adminGuard;
        this.audit = audit;
    }

    @GetMapping
    public StatusResponse status(@PathVariable String userId, @AuthenticationPrincipal Jwt jwt,
                                 @RequestHeader(name = UserTokenVerifier.HEADER, required = false) String userToken) {
        checkUserId(userId);
        Caller caller = caller(jwt);
        MfaProps.Client client = client(caller);
        userTokens.verify(jwt.getClaimAsString("iss"), caller, client, userId, userToken);
        return new StatusResponse(mfa.isEnrolled(caller.realm(), userId), client.enforce(), client.requiresInvite());
    }

    @PostMapping("/verify")
    public ResultResponse verify(@PathVariable String userId, @Valid @RequestBody CodeRequest req,
                                 @AuthenticationPrincipal Jwt jwt,
                                 @RequestHeader(name = UserTokenVerifier.HEADER, required = false) String userToken) {
        checkUserId(userId);
        Caller caller = caller(jwt);
        userTokens.verify(jwt.getClaimAsString("iss"), caller, client(caller), userId, userToken);
        return new ResultResponse(mfa.verify(caller.realm(), userId, req.code()));
    }

    @PostMapping("/enroll/start")
    public EnrollStartResponse enrollStart(@PathVariable String userId, @Valid @RequestBody EnrollStartRequest req,
                                           @AuthenticationPrincipal Jwt jwt, HttpServletRequest http,
                                 @RequestHeader(name = UserTokenVerifier.HEADER, required = false) String userToken) {
        checkUserId(userId);
        Caller caller = caller(jwt);
        MfaProps.Client client = client(caller);
        userTokens.verify(jwt.getClaimAsString("iss"), caller, client, userId, userToken);
        MfaService.StartOutcome out = mfa.startEnrollment(caller.realm(), userId, client.issuerLabel(),
                req.accountName(), client.requiresInvite(), req.inviteCode());
        AuditService.Ctx ctx = new AuditService.Ctx(caller.clientId(), null, http.getRemoteAddr());
        switch (out.status()) {
            case OK:
                audit.record("ENROLL_STARTED", caller.realm(), userId, ctx,
                        client.requiresInvite() ? "invite-used" : "no-invite-required");
                return new EnrollStartResponse(out.start().secret(), out.start().otpauthUri());
            case ALREADY_ENROLLED:
                throw new ResponseStatusException(HttpStatus.CONFLICT, "MFA already enrolled");
            default:
                audit.record("INVITE_REJECTED", caller.realm(), userId, ctx, "wrong-or-expired");
                // 422 (ไม่ใช่ 403) เพื่อให้ผู้เรียกแยกจาก "client/token ไม่ได้รับอนุญาต"
                throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "Invalid invite code");
        }
    }

    /**
     * admin ออกรหัสเชิญให้ user (ผู้เรียกต้องเป็น client ที่ admin: true; ไม่ต้องแนบ token ของ user)
     * ส่งรหัสให้ user ผ่านช่องทางอื่นที่ไม่ใช่หน้า login (เช่น เจ้าหน้าที่แจ้งทางโทรศัพท์/ที่ทำงาน)
     */
    @PostMapping("/invite")
    public InviteResponse invite(@PathVariable String userId, @AuthenticationPrincipal Jwt jwt, HttpServletRequest http,
                                 @RequestHeader(name = AdminGuard.ACTOR_HEADER, required = false) String actor) {
        checkUserId(userId);
        Caller caller = caller(jwt);
        AuditService.Ctx ctx = adminGuard.check(client(caller), actor, http.getRemoteAddr(), "INVITE_ISSUED");
        return mfa.createInvite(caller.realm(), userId, ctx)
                .map(i -> new InviteResponse(i.code(), i.expiresAt()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.CONFLICT, "MFA already enrolled; reset first"));
    }

    /** admin ล้าง MFA ของ user (เช่นทำเครื่องหาย) แล้วออกรหัสเชิญใหม่ให้ enroll ใหม่ */
    @DeleteMapping
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void reset(@PathVariable String userId, @AuthenticationPrincipal Jwt jwt, HttpServletRequest http,
                      @RequestHeader(name = AdminGuard.ACTOR_HEADER, required = false) String actor) {
        checkUserId(userId);
        Caller caller = caller(jwt);
        AuditService.Ctx ctx = adminGuard.check(client(caller), actor, http.getRemoteAddr(), "MFA_RESET");
        mfa.reset(caller.realm(), userId, ctx);
    }

    @PostMapping("/enroll/confirm")
    public ResultResponse enrollConfirm(@PathVariable String userId, @Valid @RequestBody CodeRequest req,
                                        @AuthenticationPrincipal Jwt jwt, HttpServletRequest http,
                                 @RequestHeader(name = UserTokenVerifier.HEADER, required = false) String userToken) {
        checkUserId(userId);
        Caller caller = caller(jwt);
        userTokens.verify(jwt.getClaimAsString("iss"), caller, client(caller), userId, userToken);
        MfaService.Result result = mfa.confirmEnrollment(caller.realm(), userId, req.code());
        if (result == MfaService.Result.OK) {
            audit.record("ENROLL_CONFIRMED", caller.realm(), userId,
                    new AuditService.Ctx(caller.clientId(), null, http.getRemoteAddr()), "ok");
        }
        return new ResultResponse(result);
    }

    /** ตัวตนของผู้เรียกจาก token + ตรวจว่า token นี้ออกมาเพื่อเรียก service นี้ (aud) */
    private Caller caller(Jwt jwt) {
        Caller caller = Caller.from(jwt);
        String required = props.requiredAudience();
        if (required != null && !required.isBlank()
                && (jwt.getAudience() == null || !jwt.getAudience().contains(required))) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Token audience not allowed");
        }
        return caller;
    }

    private MfaProps.Client client(Caller caller) {
        return props.findClient(caller.realm(), caller.clientId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.FORBIDDEN, "Client not allowed"));
    }

    private static void checkUserId(String userId) {
        if (!userId.matches("[A-Za-z0-9._-]{1,64}")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid user id");
        }
    }
}
