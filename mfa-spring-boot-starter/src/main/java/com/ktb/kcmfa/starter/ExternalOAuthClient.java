package com.ktb.kcmfa.starter;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Client ของ OAuth 2.0 / OIDC provider ภายนอก (ไม่ใช่ Keycloak) ตั้งค่าด้วย kcmfa.oauth.*
 * ใช้เฉพาะขั้น "พิสูจน์ตัวตนขั้นแรก" แทน password grant ส่วน MFA ยังตรวจที่ MFA service กลางเหมือนเดิม
 */
public class ExternalOAuthClient {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ParameterizedTypeReference<Map<String, Object>> MAP = new ParameterizedTypeReference<>() {};

    private final KcMfaProperties.OAuth cfg;
    private final RestClient rest;

    public ExternalOAuthClient(KcMfaProperties props) {
        this.cfg = props.oauth();
        this.rest = Http.client(props);
    }

    /** URL หน้า login ของ provider (Authorization Code + PKCE S256) */
    public String authorizationUrl(String state, String nonce, String codeChallenge) {
        String uri = cfg.authorizationUri();
        return uri + (uri.contains("?") ? "&" : "?")
                + "response_type=code"
                + "&client_id=" + enc(cfg.clientId())
                + "&redirect_uri=" + enc(cfg.redirectUri())
                + "&scope=" + enc(cfg.scope())
                + "&state=" + enc(state)
                + "&nonce=" + enc(nonce)
                + "&code_challenge=" + enc(codeChallenge)
                + "&code_challenge_method=S256";
    }

    /** แลก authorization code เป็น token @return empty ถ้า code ใช้ไม่ได้ (หมดอายุ/ใช้แล้ว/verifier ไม่ตรง) */
    public Optional<Map<String, Object>> authorizationCodeGrant(String code, String codeVerifier) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("code", code);
        form.add("redirect_uri", cfg.redirectUri());
        form.add("code_verifier", codeVerifier);
        try {
            Map<String, Object> body = postForm(cfg.tokenUri(), form);
            return body == null || body.get("access_token") == null ? Optional.empty() : Optional.of(body);
        } catch (HttpClientErrorException e) {
            int s = e.getStatusCode().value();
            if (s == 400 || s == 401) {
                return Optional.empty();
            }
            throw e;
        }
    }

    /** ข้อมูล user จาก userinfo endpoint (ใช้เมื่อ provider ไม่ออก id_token) */
    public Map<String, Object> userInfo(String accessToken) {
        if (blank(cfg.userInfoUri())) {
            throw new IllegalStateException("Provider returned no id_token and kcmfa.oauth.user-info-uri is not set");
        }
        Map<String, Object> body = rest.get().uri(cfg.userInfoUri())
                .accept(MediaType.APPLICATION_JSON)
                .headers(h -> h.setBearerAuth(accessToken))
                .retrieve()
                .body(MAP);
        if (body == null) {
            throw new IllegalStateException("Empty userinfo response");
        }
        return body;
    }

    /** ยกเลิก token ที่ provider (RFC 7009) แบบ best effort ไม่ทำอะไรถ้าไม่ได้ตั้ง kcmfa.oauth.revocation-uri */
    public void revoke(Map<String, Object> tokens) {
        if (blank(cfg.revocationUri()) || tokens == null) {
            return;
        }
        Object token = tokens.get("refresh_token") != null ? tokens.get("refresh_token") : tokens.get("access_token");
        if (token == null) {
            return;
        }
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("token", token.toString());
        try {
            postForm(cfg.revocationUri(), form);
        } catch (Exception ignored) {
            // best effort
        }
    }

    /**
     * อ่าน payload ของ id_token โดยไม่ verify signature
     * ทำได้เฉพาะ token ที่เพิ่งได้จาก token endpoint โดยตรงผ่าน TLS (OIDC Core 3.1.3.7) ห้ามใช้กับ token ที่มาจาก browser
     */
    public static Map<String, Object> jwtClaims(String jwt) {
        try {
            byte[] payload = Base64.getUrlDecoder().decode(jwt.split("\\.")[1].getBytes(StandardCharsets.UTF_8));
            return JSON.readValue(payload, new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalStateException("Cannot read id_token", e);
        }
    }

    private Map<String, Object> postForm(String url, MultiValueMap<String, String> form) {
        boolean basic = "basic".equalsIgnoreCase(cfg.clientAuth());
        if (!basic) {
            form.add("client_id", cfg.clientId());
            form.add("client_secret", cfg.clientSecret());
        }
        return rest.post().uri(url)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .headers((HttpHeaders h) -> {
                    if (basic) {
                        h.setBasicAuth(cfg.clientId(), cfg.clientSecret());
                    }
                })
                .body(form)
                .retrieve()
                .body(MAP);
    }

    private static boolean blank(String s) {
        return s == null || s.isBlank();
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
