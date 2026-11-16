package com.ktb.demo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.SupplierJwtDecoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.header.writers.StaticHeadersWriter;

import com.ktb.kcmfa.starter.KcMfaProperties;

import jakarta.servlet.http.Cookie;

/**
 * API ของเว็บ: ต้องมี access token ของ Keycloak (ตรวจลายเซ็น/iss/exp + azp ด้วย LoginTokenValidator)
 * token มาได้สองทาง: header Authorization: Bearer (เช่น curl/Postman) หรือ cookie httpOnly ที่ AuthController ตั้งให้
 *
 * CSRF ปิดไว้ได้เพราะ cookie เป็น SameSite=Strict และ endpoint ที่ใช้ cookie ยืนยันตัวตนเป็น GET ที่ไม่แก้ข้อมูล
 * ถ้าเพิ่ม endpoint ที่เปลี่ยนข้อมูล (POST/PUT/DELETE) ที่รับ cookie ต้องเปิด CSRF กลับ
 * /api/auth/** เปิดให้เรียกได้โดยไม่ต้องมี token เพราะเป็นทางที่ใช้ขอ token
 *
 * CSP: สคริปต์/สไตล์ต้องมาจาก origin เดียวกันเท่านั้น (ไม่มี inline) จึงต้องแยก style.css / app.js เป็นไฟล์
 */
@Configuration
public class SecurityConfig {

    private static final String CSP = "default-src 'none'; script-src 'self'; style-src 'self'; "
            + "img-src 'self' blob: data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

    @Bean
    SecurityFilterChain api(HttpSecurity http, BearerTokenResolver resolver) throws Exception {
        http
            .csrf(c -> c.disable())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .headers(h -> h
                .contentSecurityPolicy(c -> c.policyDirectives(CSP))
                .referrerPolicy(r -> r.policy(ReferrerPolicy.NO_REFERRER))
                .addHeaderWriter(new StaticHeadersWriter("Permissions-Policy", "camera=(), microphone=(), geolocation=()")))
            .authorizeHttpRequests(a -> a
                .requestMatchers("/", "/index.html", "/app.js", "/style.css", "/error").permitAll()
                .requestMatchers("/api/auth/**").permitAll()
                .anyRequest().authenticated())
            .oauth2ResourceServer(o -> o.bearerTokenResolver(resolver).jwt(j -> { }));
        return http.build();
    }

    /** decoder ของเราเอง (แทนที่ Boot สร้างจาก issuer-uri) เพื่อเพิ่ม validator ของ azp; โหลด JWKS แบบ lazy ตอนมี request แรก */
    @Bean
    JwtDecoder jwtDecoder(@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuer,
                          KcMfaProperties kcmfa) {
        return new SupplierJwtDecoder(() -> {
            NimbusJwtDecoder decoder = JwtDecoders.fromIssuerLocation(issuer);
            decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                    JwtValidators.createDefaultWithIssuer(issuer),
                    new LoginTokenValidator(kcmfa.keycloak().clientId())));
            return decoder;
        });
    }

    @Bean
    BearerTokenResolver bearerTokenResolver() {
        DefaultBearerTokenResolver header = new DefaultBearerTokenResolver();
        return request -> {
            String token = header.resolve(request);
            if (token != null || request.getCookies() == null) {
                return token;
            }
            for (Cookie c : request.getCookies()) {
                if (AuthController.COOKIE.equals(c.getName()) && !c.getValue().isBlank()) {
                    return c.getValue();
                }
            }
            return null;
        };
    }
}
