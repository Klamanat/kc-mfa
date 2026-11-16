package com.ktb.kcmfa.starter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class OAuthLoginFlowTest {

    private final KeycloakClient kc = mock(KeycloakClient.class);
    private final ExternalOAuthClient oauth = mock(ExternalOAuthClient.class);
    private final MfaServiceClient mfa = mock(MfaServiceClient.class);

    // ค่าที่ flow ส่งให้ provider ตอน start()
    private String state;
    private String nonce;
    private String challenge;
    private String userId;

    private OAuthLoginFlow flow(Duration resultTtl) {
        KcMfaProperties props = new KcMfaProperties(
                new KcMfaProperties.Keycloak("http://kc/auth", "realm", "client", "secret"),
                new KcMfaProperties.MfaService("http://mfa"),
                Duration.ofMinutes(5), 5,
                Duration.ofSeconds(2), Duration.ofSeconds(5), Duration.ofSeconds(30),
                new KcMfaProperties.OAuth(true, "idp", "https://idp.example.com/authorize",
                        "https://idp.example.com/token", "https://idp.example.com/userinfo", null,
                        "web1", "secret", "post", "https://web1.example.com/api/auth/oauth/callback",
                        "openid", "sub", "email", "/", "/login",
                        Duration.ofMinutes(5), resultTtl, true, "/"),
                "memory", null, null, false);
        when(oauth.authorizationUrl(anyString(), anyString(), anyString())).thenAnswer(inv -> {
            state = inv.getArgument(0);
            nonce = inv.getArgument(1);
            challenge = inv.getArgument(2);
            return "https://idp.example.com/authorize";
        });
        LoginFlow loginFlow = new LoginFlow(kc, mfa, new InMemoryChallengeStore(), props, new SessionRevoker(kc, oauth));
        OAuthLoginFlow f = new OAuthLoginFlow(oauth, loginFlow, new InMemoryOAuthStateStore(), props);
        userId = f.userIdOf("ext|user 1");
        return f;
    }

    private static String jwt(String json) {
        return "h." + Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8)) + ".s";
    }

    private static Map<String, Object> tokens(String nonce, String aud) {
        return Map.of(
                "access_token", "opaque-at",
                "id_token", jwt("{\"sub\":\"ext|user 1\",\"email\":\"john@example.com\",\"aud\":\"" + aud
                        + "\",\"nonce\":\"" + nonce + "\"}"),
                "refresh_token", "r1");
    }

    private void providerReturns(Map<String, Object> tokens) {
        when(oauth.authorizationCodeGrant(anyString(), anyString())).thenReturn(Optional.of(tokens));
    }

    private static int statusOf(Runnable r) {
        return assertThrows(ResponseStatusException.class, r::run).getStatusCode().value();
    }

    @Test
    void userIdIsNamespacedAndAcceptedByMfaService() {
        flow(Duration.ofMinutes(1));
        assertTrue(userId.startsWith("idp."));
        assertTrue(userId.matches("[A-Za-z0-9._-]{1,64}"));   // รูปแบบเดียวกับ MfaController.checkUserId
    }

    @Test
    void codeFlowEndsInMfaChallengeAndResultIsSingleUse() {
        OAuthLoginFlow flow = flow(Duration.ofMinutes(1));
        when(mfa.status(eq(userId), any())).thenReturn(new MfaServiceClient.Status(true, false, false));

        OAuthLoginFlow.Start s = flow.start();
        providerReturns(tokens(nonce, "web1"));
        String handle = flow.callback("code1", state, s.cookieValue());

        LoginFlow.LoginResult r = flow.result(handle);
        assertEquals("MFA_REQUIRED", r.status());
        assertNotNull(r.challengeId());
        assertNull(r.tokens());
        assertEquals(401, statusOf(() -> flow.result(handle)));
    }

    @Test
    void sendsProvidersIdTokenAsProof() {
        OAuthLoginFlow flow = flow(Duration.ofMinutes(1));
        OAuthLoginFlow.Start s = flow.start();
        Map<String, Object> tokens = tokens(nonce, "web1");
        providerReturns(tokens);
        when(mfa.status(userId, (String) tokens.get("id_token"))).thenReturn(new MfaServiceClient.Status(true, false, false));

        assertEquals("MFA_REQUIRED", flow.result(flow.callback("c", state, s.cookieValue())).status());
    }

    @Test
    void sendsS256ChallengeOfTheVerifierUsedAtTokenEndpoint() {
        OAuthLoginFlow flow = flow(Duration.ofMinutes(1));
        when(mfa.status(eq(userId), any())).thenReturn(new MfaServiceClient.Status(false, false, false));
        OAuthLoginFlow.Start s = flow.start();
        when(oauth.authorizationCodeGrant(anyString(), anyString())).thenAnswer(inv -> {
            assertEquals(challenge, OAuthLoginFlow.s256(inv.getArgument(1)));
            return Optional.of(tokens(nonce, "web1"));
        });

        LoginFlow.LoginResult r = flow.result(flow.callback("c", state, s.cookieValue()));
        assertEquals("OK", r.status());
        assertNotNull(r.tokens().get("access_token"));
    }

    @Test
    void usesUserInfoWhenProviderHasNoIdToken() {
        OAuthLoginFlow flow = flow(Duration.ofMinutes(1));
        when(mfa.status(eq(userId), any())).thenReturn(new MfaServiceClient.Status(false, true, false));
        OAuthLoginFlow.Start s = flow.start();
        providerReturns(Map.of("access_token", "opaque-at"));
        when(oauth.userInfo("opaque-at")).thenReturn(Map.of("sub", "ext|user 1", "email", "john@example.com"));

        assertEquals("ENROLL_REQUIRED", flow.result(flow.callback("c", state, s.cookieValue())).status());
    }

    @Test
    void rejectsCallbackFromAnotherBrowserAndDoesNotExchangeCode() {
        OAuthLoginFlow flow = flow(Duration.ofMinutes(1));
        flow.start();
        assertEquals(401, statusOf(() -> flow.callback("code1", state, "other-browser")));
        flow.start();
        assertEquals(401, statusOf(() -> flow.callback("code1", state, null)));
        verify(oauth, never()).authorizationCodeGrant(any(), any());
    }

    @Test
    void stateIsSingleUseAndUnknownStateIsRejected() {
        OAuthLoginFlow flow = flow(Duration.ofMinutes(1));
        when(mfa.status(eq(userId), any())).thenReturn(new MfaServiceClient.Status(true, false, false));
        OAuthLoginFlow.Start s = flow.start();
        providerReturns(tokens(nonce, "web1"));

        flow.callback("code1", state, s.cookieValue());
        assertEquals(401, statusOf(() -> flow.callback("code1", state, s.cookieValue())));
        assertEquals(401, statusOf(() -> flow.callback("code1", "nope", s.cookieValue())));
        assertEquals(401, statusOf(() -> flow.callback("code1", null, s.cookieValue())));
    }

    @Test
    void rejectedOrMissingCodeIs401() {
        OAuthLoginFlow flow = flow(Duration.ofMinutes(1));
        OAuthLoginFlow.Start s = flow.start();
        when(oauth.authorizationCodeGrant(anyString(), anyString())).thenReturn(Optional.empty());
        assertEquals(401, statusOf(() -> flow.callback("bad", state, s.cookieValue())));
        OAuthLoginFlow.Start s2 = flow.start();
        assertEquals(401, statusOf(() -> flow.callback(null, state, s2.cookieValue())));   // เช่น user กดยกเลิกที่ provider
    }

    @Test
    void nonceOrAudienceMismatchRevokesAtProvider() {
        OAuthLoginFlow flow = flow(Duration.ofMinutes(1));
        OAuthLoginFlow.Start s = flow.start();
        providerReturns(tokens("wrong", "web1"));
        assertEquals(401, statusOf(() -> flow.callback("c", state, s.cookieValue())));

        OAuthLoginFlow.Start s2 = flow.start();
        providerReturns(tokens(nonce, "another-client"));
        assertEquals(401, statusOf(() -> flow.callback("c", state, s2.cookieValue())));

        verify(mfa, never()).status(anyString(), any());
        verify(kc, never()).logout(any());
    }

    @Test
    void failsClosedWhenMfaServiceIsDownAndNeverSendsExternalTokenToKeycloak() {
        OAuthLoginFlow flow = flow(Duration.ofMinutes(1));
        when(mfa.status(eq(userId), any())).thenThrow(new IllegalStateException("down"));
        OAuthLoginFlow.Start s = flow.start();
        providerReturns(tokens(nonce, "web1"));

        assertEquals(503, statusOf(() -> flow.callback("c", state, s.cookieValue())));
        verify(oauth).revoke(anyMap());
        verify(kc, never()).logout(any());
    }

    @Test
    void sweepRevokesOkResultNobodyCollected() {
        OAuthLoginFlow flow = flow(Duration.ofMillis(-1));
        when(mfa.status(eq(userId), any())).thenReturn(new MfaServiceClient.Status(false, false, false));
        OAuthLoginFlow.Start s = flow.start();
        providerReturns(tokens(nonce, "web1"));
        String handle = flow.callback("c", state, s.cookieValue());

        flow.sweepExpired();
        verify(oauth).revoke(anyMap());
        assertEquals(401, statusOf(() -> flow.result(handle)));
    }
}
