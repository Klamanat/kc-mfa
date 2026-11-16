package com.ktb.kcmfa.starter;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

/**
 * เรียก MFA service กลางด้วย token ของ service account ตัวเอง
 * (realm และ client ที่ service เห็นมาจาก token ไม่ใช่จากค่าที่ส่งใน request)
 * userToken = access token ของ user (Keycloak) หรือ id_token (OAuth provider ภายนอก) ที่เพิ่งได้จากการ login
 * เมธอดทั้งหมด throw RuntimeException ถ้าเรียกไม่สำเร็จ ผู้เรียกต้อง fail-closed
 */
public class MfaServiceClient {

    public record Status(boolean enrolled, boolean enforce) {}
    public record EnrollStart(String secret, String otpauthUri) {}
    public record ResultBody(MfaResult result) {}

    private static final String BASE = "/v1/users/{id}/mfa";
    private static final String USER_TOKEN_HEADER = "X-User-Token";

    private final RestClient rest;
    private final ServiceTokenProvider tokens;

    public MfaServiceClient(KcMfaProperties props, ServiceTokenProvider tokens) {
        this.rest = Http.builder(props).baseUrl(props.mfaService().url()).build();
        this.tokens = tokens;
    }

    public Status status(String userId, String userToken) {
        return Objects.requireNonNull(rest.get().uri(BASE, userId)
                .headers(h -> auth(h, userToken))
                .retrieve()
                .body(Status.class));
    }

    public MfaResult verify(String userId, String code, String userToken) {
        return post(BASE + "/verify", userId, Map.of("code", code), userToken);
    }

    /** @return empty ถ้า user มี MFA อยู่แล้ว (service ตอบ 409) */
    public Optional<EnrollStart> enrollStart(String userId, String accountName, String userToken) {
        try {
            return Optional.of(Objects.requireNonNull(rest.post().uri(BASE + "/enroll/start", userId)
                    .headers(h -> auth(h, userToken))
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("accountName", accountName))
                    .retrieve()
                    .body(EnrollStart.class)));
        } catch (HttpClientErrorException.Conflict e) {
            return Optional.empty();
        }
    }

    public MfaResult enrollConfirm(String userId, String code, String userToken) {
        return post(BASE + "/enroll/confirm", userId, Map.of("code", code), userToken);
    }

    /** token ของ service account + token ของ user (หลักฐานว่า user ผ่านปัจจัยแรกแล้ว service ตรวจลายเซ็นเอง) */
    private void auth(HttpHeaders h, String userToken) {
        h.setBearerAuth(tokens.get());
        if (userToken != null) {
            h.set(USER_TOKEN_HEADER, userToken);
        }
    }

    private MfaResult post(String path, String userId, Map<String, String> body, String userToken) {
        ResultBody r = rest.post().uri(path, userId)
                .headers(h -> auth(h, userToken))
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .retrieve()
                .body(ResultBody.class);
        return Objects.requireNonNull(r).result();
    }
}
