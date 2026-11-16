package com.ktb.kcmfa.starter;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/** เรียก token endpoint ของ Keycloak (realm ของเว็บนี้) จาก backend เท่านั้น */
public class KeycloakClient {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final KcMfaProperties.Keycloak kc;
    private final RestClient rest;

    public KeycloakClient(KcMfaProperties props) {
        this.kc = props.keycloak();
        this.rest = Http.client(props);
    }

    /** @return token response หรือ empty ถ้า username/password ผิด */
    public Optional<Map<String, Object>> passwordGrant(String username, String password) {
        MultiValueMap<String, String> form = clientForm();
        form.add("grant_type", "password");
        form.add("username", username);
        form.add("password", password);
        try {
            return Optional.ofNullable(postForm(kc.tokenUrl(), form));
        } catch (HttpClientErrorException e) {
            int s = e.getStatusCode().value();
            if (s == 400 || s == 401) {
                return Optional.empty(); // invalid_grant / account not fully set up ฯลฯ
            }
            throw e;
        }
    }

    /** token ของ service account (ใช้เรียก MFA service) */
    public Map<String, Object> clientCredentials() {
        MultiValueMap<String, String> form = clientForm();
        form.add("grant_type", "client_credentials");
        Map<String, Object> body = postForm(kc.tokenUrl(), form);
        if (body == null || body.get("access_token") == null) {
            throw new IllegalStateException("Keycloak returned no access_token for client_credentials");
        }
        return body;
    }

    /** ยกเลิก session ที่ Keycloak (ใช้เมื่อ challenge หมดอายุ/ถูกล็อก เพื่อไม่ให้ token ค้าง) */
    public void logout(String refreshToken) {
        if (refreshToken == null) {
            return;
        }
        MultiValueMap<String, String> form = clientForm();
        form.add("refresh_token", refreshToken);
        try {
            rest.post().uri(kc.logoutUrl())
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .toBodilessEntity();
        } catch (Exception ignored) {
            // best effort
        }
    }

    /**
     * อ่าน claim "sub" จาก access token โดยไม่ verify signature
     * ปลอดภัยเฉพาะกรณีนี้เพราะ token เพิ่งได้จาก Keycloak ผ่าน TLS โดยตรง
     * (ห้ามใช้กับ token ที่มาจาก client)
     */
    public static String subjectOf(Map<String, Object> tokenResponse) {
        try {
            String at = (String) tokenResponse.get("access_token");
            String payload = at.split("\\.")[1];
            JsonNode n = JSON.readTree(Base64.getUrlDecoder().decode(payload.getBytes(StandardCharsets.UTF_8)));
            return n.get("sub").asText();
        } catch (Exception e) {
            throw new IllegalStateException("Cannot read subject from Keycloak token", e);
        }
    }

    private MultiValueMap<String, String> clientForm() {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", kc.clientId());
        form.add("client_secret", kc.clientSecret());
        return form;
    }

    private Map<String, Object> postForm(String url, MultiValueMap<String, String> form) {
        return rest.post().uri(url)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(new ParameterizedTypeReference<Map<String, Object>>() {});
    }
}
