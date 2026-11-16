package com.ktb.demo;

import java.util.List;
import java.util.Map;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** endpoint ตัวอย่างที่ถูกป้องกัน: เข้าได้เมื่อ login + ผ่าน MFA แล้วเท่านั้น (ได้ access token มาแล้ว) */
@RestController
@RequestMapping("/api")
public class ApiController {

    @GetMapping("/me")
    public Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
        return Map.of(
                "sub", jwt.getSubject(),
                "username", String.valueOf(jwt.getClaimAsString("preferred_username")),
                "issuer", String.valueOf(jwt.getIssuer()),
                "expiresAt", String.valueOf(jwt.getExpiresAt()));
    }

    @GetMapping("/orders")
    public List<Map<String, Object>> orders(@AuthenticationPrincipal Jwt jwt) {
        return List.of(
                Map.of("id", 1001, "owner", jwt.getSubject(), "item", "Coffee", "amount", 120),
                Map.of("id", 1002, "owner", jwt.getSubject(), "item", "Tea", "amount", 90));
    }
}
