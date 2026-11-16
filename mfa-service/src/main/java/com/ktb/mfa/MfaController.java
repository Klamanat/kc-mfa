package com.ktb.mfa;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

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

    public record StatusResponse(boolean enrolled, boolean enforce) {}
    public record CodeRequest(@NotBlank @Size(max = 16) String code) {}
    public record EnrollStartRequest(@NotBlank @Size(max = 256) String accountName) {}
    public record ResultResponse(MfaService.Result result) {}
    public record EnrollStartResponse(String secret, String otpauthUri) {}

    private final MfaService mfa;
    private final MfaProps props;
    private final UserTokenVerifier userTokens;

    public MfaController(MfaService mfa, MfaProps props, UserTokenVerifier userTokens) {
        this.mfa = mfa;
        this.props = props;
        this.userTokens = userTokens;
    }

    @GetMapping
    public StatusResponse status(@PathVariable String userId, @AuthenticationPrincipal Jwt jwt,
                                 @RequestHeader(name = UserTokenVerifier.HEADER, required = false) String userToken) {
        checkUserId(userId);
        Caller caller = caller(jwt);
        MfaProps.Client client = client(caller);
        userTokens.verify(jwt.getClaimAsString("iss"), caller, client, userId, userToken);
        return new StatusResponse(mfa.isEnrolled(caller.realm(), userId), client.enforce());
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
                                           @AuthenticationPrincipal Jwt jwt,
                                 @RequestHeader(name = UserTokenVerifier.HEADER, required = false) String userToken) {
        checkUserId(userId);
        Caller caller = caller(jwt);
        MfaProps.Client client = client(caller);
        userTokens.verify(jwt.getClaimAsString("iss"), caller, client, userId, userToken);
        return mfa.startEnrollment(caller.realm(), userId, client.issuerLabel(), req.accountName())
                .map(e -> new EnrollStartResponse(e.secret(), e.otpauthUri()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.CONFLICT, "MFA already enrolled"));
    }

    @PostMapping("/enroll/confirm")
    public ResultResponse enrollConfirm(@PathVariable String userId, @Valid @RequestBody CodeRequest req,
                                        @AuthenticationPrincipal Jwt jwt,
                                 @RequestHeader(name = UserTokenVerifier.HEADER, required = false) String userToken) {
        checkUserId(userId);
        Caller caller = caller(jwt);
        userTokens.verify(jwt.getClaimAsString("iss"), caller, client(caller), userId, userToken);
        return new ResultResponse(mfa.confirmEnrollment(caller.realm(), userId, req.code()));
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
