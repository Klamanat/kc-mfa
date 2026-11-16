package com.ktb.mfa;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiFunction;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

/**
 * หลักฐานว่า user คนนี้ผ่านปัจจัยแรกจริง: backend ต้องแนบ token ของ user (header X-User-Token) มากับทุก request
 * service ตรวจลายเซ็นเองและดูว่า token นั้นเป็นของ userId ที่ขอ
 *
 * ถ้าไม่มีการตรวจนี้ backend (หรือ client secret ของเว็บ) ที่ถูกเจาะจะสั่งล็อกบัญชีหรือลงทะเบียน MFA แทน user คนไหนใน realm ก็ได้
 * เมื่อมีแล้ว ทำได้เฉพาะกับ user ที่เพิ่ง login ผ่านเว็บนั้นจริงภายในช่วง user-token-grace
 *
 *   user ของ Keycloak      access token ของ user: iss = realm ของผู้เรียก, azp = client ของเว็บ, sub = userId
 *   user จาก OAuth ภายนอก  userId รูปแบบ "{provider}.{base64url(SHA-256(sub))}": id_token ของ provider ที่ตั้งไว้ใน
 *                          mfa.clients[].external-providers (ตรวจลายเซ็นกับ JWKS ของ issuer, aud, และ hash ของ sub)
 *
 * token หมดอายุแล้วยังรับได้อีก user-token-grace เพราะ user ใช้เวลากรอก OTP / สแกน QR หลังได้ token มาแล้ว
 */
@Component
public class UserTokenVerifier {

    public static final String HEADER = "X-User-Token";

    private final Duration grace;
    private final BiFunction<String, Duration, JwtDecoder> decoderFactory;
    private final ConcurrentHashMap<String, JwtDecoder> decoders = new ConcurrentHashMap<>();

    @Autowired
    public UserTokenVerifier(MfaProps props) {
        this(props, UserTokenVerifier::discover);
    }

    /** สำหรับเทสต์: ใส่ตัวสร้าง JwtDecoder เองได้ */
    UserTokenVerifier(MfaProps props, BiFunction<String, Duration, JwtDecoder> decoderFactory) {
        this.grace = props.userTokenGrace() == null ? Duration.ofMinutes(15) : props.userTokenGrace();
        this.decoderFactory = decoderFactory;
    }

    /** @param callerIssuer iss ของ token ผู้เรียก (ผ่านการตรวจกับ mfa.trusted-issuers แล้ว) */
    public void verify(String callerIssuer, Caller caller, MfaProps.Client client, String userId, String userToken) {
        int dot = userId.indexOf('.');
        if (dot < 0) {
            verifyKeycloakUser(callerIssuer, caller, client, userId, userToken);
            return;
        }
        String provider = userId.substring(0, dot);
        MfaProps.ExternalProvider cfg = client.externalProvider(provider)
                .orElseThrow(() -> forbidden("External provider not allowed for this client"));
        if (cfg.issuer() == null || cfg.issuer().isBlank()) {
            return;   // provider ที่ไม่ออก id_token: ผู้ดูแลเลือกยอมรับแบบไม่มีหลักฐานไว้ใน config เอง
        }
        Jwt token = decode(cfg.issuer(), userToken);
        if (cfg.audience() != null && !cfg.audience().isBlank()
                && (token.getAudience() == null || !token.getAudience().contains(cfg.audience()))) {
            throw forbidden("User token audience mismatch");
        }
        String subject = token.getSubject();
        if (subject == null || !userId.equals(provider + "." + sha256(subject))) {
            throw forbidden("User token does not belong to this user");
        }
    }

    private void verifyKeycloakUser(String callerIssuer, Caller caller, MfaProps.Client client,
                                    String userId, String userToken) {
        Jwt token = decode(callerIssuer, userToken);
        String azp = token.getClaimAsString("azp");
        List<String> loginClients = client.loginClientIds() == null ? List.of() : client.loginClientIds();
        if (azp == null || !(azp.equals(caller.clientId()) || loginClients.contains(azp))) {
            throw forbidden("User token was not issued to this client");
        }
        if (!userId.equals(token.getSubject())) {
            throw forbidden("User token does not belong to this user");
        }
    }

    private Jwt decode(String issuer, String token) {
        if (token == null || token.isBlank()) {
            throw forbidden("Missing " + HEADER);
        }
        JwtDecoder decoder;
        try {
            decoder = decoders.computeIfAbsent(issuer, i -> decoderFactory.apply(i, grace));
        } catch (RuntimeException e) {
            // อ่าน metadata/JWKS ของ issuer ไม่ได้: ให้ผู้เรียก fail-closed
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Cannot load keys of token issuer", e);
        }
        try {
            return decoder.decode(token);
        } catch (JwtException e) {
            throw forbidden("Invalid user token");
        }
    }

    /** JwtDecoder จาก metadata ของ issuer (OIDC discovery) ตรวจลายเซ็น, iss และเวลาโดยยอมให้หมดอายุไม่เกิน grace */
    private static JwtDecoder discover(String issuer, Duration grace) {
        NimbusJwtDecoder decoder = JwtDecoders.fromIssuerLocation(issuer);
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(grace), new JwtIssuerValidator(issuer)));
        return decoder;
    }

    static String sha256(String s) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(d);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static ResponseStatusException forbidden(String message) {
        return new ResponseStatusException(HttpStatus.FORBIDDEN, message);
    }
}
