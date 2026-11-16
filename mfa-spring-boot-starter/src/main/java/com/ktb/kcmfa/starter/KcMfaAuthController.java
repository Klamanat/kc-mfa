package com.ktb.kcmfa.starter;

import java.util.Map;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Endpoint สำหรับหน้าเว็บ (path เปลี่ยนได้ด้วย kcmfa.base-path)
 *   POST login                {username,password}
 *   POST mfa/verify           {challengeId, code}
 *   POST mfa/enroll/start     {challengeId}
 *   POST mfa/enroll/confirm   {challengeId, code}
 *
 * production: ส่ง tokens เป็น httpOnly+Secure cookie แทน JSON body และใส่ CSRF + rate limit ต่อ IP
 * ถ้าเว็บมี controller ของตัวเองอยู่แล้ว ปิดตัวนี้ด้วย kcmfa.controller.enabled=false แล้วฉีด LoginFlow ไปใช้เอง
 */
@RestController
@RequestMapping("${kcmfa.base-path:/api/auth}")
public class KcMfaAuthController {

    public record LoginRequest(@NotBlank @Size(max = 256) String username,
                               @NotBlank @Size(max = 1024) String password) {}
    public record ChallengeRequest(@NotBlank @Size(max = 128) String challengeId) {}
    public record CodeRequest(@NotBlank @Size(max = 128) String challengeId,
                              @NotBlank @Size(max = 16) String code) {}

    private final LoginFlow flow;

    public KcMfaAuthController(LoginFlow flow) {
        this.flow = flow;
    }

    @PostMapping("/login")
    public LoginFlow.LoginResult login(@Valid @RequestBody LoginRequest req) {
        return flow.login(req.username(), req.password());
    }

    @PostMapping("/mfa/verify")
    public Map<String, Object> verify(@Valid @RequestBody CodeRequest req) {
        return flow.verify(req.challengeId(), req.code());
    }

    @PostMapping("/mfa/enroll/start")
    public MfaServiceClient.EnrollStart enrollStart(@Valid @RequestBody ChallengeRequest req) {
        return flow.enrollStart(req.challengeId());
    }

    @PostMapping("/mfa/enroll/confirm")
    public Map<String, Object> enrollConfirm(@Valid @RequestBody CodeRequest req) {
        return flow.enrollConfirm(req.challengeId(), req.code());
    }
}
