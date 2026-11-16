package com.ktb.kcmfa.starter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class LoginFlowTest {

    private KeycloakClient kc;
    private MfaServiceClient mfa;
    private LoginFlow flow;

    private static Map<String, Object> tokens() {
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"sub\":\"u1\"}".getBytes(StandardCharsets.UTF_8));
        return Map.of("access_token", "h." + payload + ".s", "refresh_token", "r1");
    }

    @BeforeEach
    void setUp() {
        kc = mock(KeycloakClient.class);
        mfa = mock(MfaServiceClient.class);
        KcMfaProperties props = new KcMfaProperties(
                new KcMfaProperties.Keycloak("http://kc/auth", "realm", "client", "secret"),
                new KcMfaProperties.MfaService("http://mfa"),
                Duration.ofMinutes(5), 2,
                Duration.ofSeconds(2), Duration.ofSeconds(5), Duration.ofSeconds(30), null, "memory", null);
        flow = new LoginFlow(kc, mfa, new InMemoryChallengeStore(), props);
        when(kc.passwordGrant("john", "pw")).thenReturn(Optional.of(tokens()));
    }

    private static int statusOf(Runnable r) {
        return assertThrows(ResponseStatusException.class, r::run).getStatusCode().value();
    }

    @Test
    void returnsTokensWhenNoMfaAndNotEnforced() {
        when(mfa.status(eq("u1"), any())).thenReturn(new MfaServiceClient.Status(false, false));
        LoginFlow.LoginResult r = flow.login("john", "pw");
        assertEquals("OK", r.status());
        assertNotNull(r.tokens());
    }

    @Test
    void requiresMfaWhenEnrolledAndHoldsTokens() {
        when(mfa.status(eq("u1"), any())).thenReturn(new MfaServiceClient.Status(true, false));
        LoginFlow.LoginResult r = flow.login("john", "pw");
        assertEquals("MFA_REQUIRED", r.status());
        assertNotNull(r.challengeId());
        assertNull(r.tokens());
    }

    @Test
    void requiresEnrollmentWhenEnforcedAndNotEnrolled() {
        when(mfa.status(eq("u1"), any())).thenReturn(new MfaServiceClient.Status(false, true));
        assertEquals("ENROLL_REQUIRED", flow.login("john", "pw").status());
    }

    @Test
    void failsClosedAndRevokesSessionWhenMfaServiceIsDown() {
        when(mfa.status(eq("u1"), any())).thenThrow(new IllegalStateException("down"));
        assertEquals(503, statusOf(() -> flow.login("john", "pw")));
        verify(kc).logout("r1");
    }

    @Test
    void wrongPasswordIs401() {
        when(kc.passwordGrant("john", "bad")).thenReturn(Optional.empty());
        assertEquals(401, statusOf(() -> flow.login("john", "bad")));
        verify(mfa, never()).status(anyString(), any());
    }

    @Test
    void verifyReleasesTokensOnlyOnce() {
        when(mfa.status(eq("u1"), any())).thenReturn(new MfaServiceClient.Status(true, false));
        when(mfa.verify(eq("u1"), eq("123456"), any())).thenReturn(MfaResult.OK);
        String id = flow.login("john", "pw").challengeId();

        assertNotNull(flow.verify(id, "123456").get("access_token"));
        assertEquals(401, statusOf(() -> flow.verify(id, "123456")));
    }

    @Test
    void tooManyBadCodesDiscardChallengeAndRevokeSession() {
        when(mfa.status(eq("u1"), any())).thenReturn(new MfaServiceClient.Status(true, false));
        when(mfa.verify(eq("u1"), eq("000000"), any())).thenReturn(MfaResult.BAD_CODE);
        String id = flow.login("john", "pw").challengeId();

        assertEquals(401, statusOf(() -> flow.verify(id, "000000")));
        verify(kc, never()).logout("r1");
        assertEquals(401, statusOf(() -> flow.verify(id, "000000")));   // ครั้งที่ 2 = maxAttempts
        verify(kc).logout("r1");
        assertEquals(401, statusOf(() -> flow.verify(id, "123456")));   // challenge หายแล้ว
    }

    @Test
    void afterPasswordWorksWithTokensFromExistingWrapper() {
        when(mfa.status(eq("u1"), any())).thenReturn(new MfaServiceClient.Status(true, false));
        LoginFlow.LoginResult r = flow.afterPassword("john", tokens());
        assertEquals("MFA_REQUIRED", r.status());
        assertNotNull(r.challengeId());
        verify(kc, never()).passwordGrant(anyString(), anyString());
    }

    @Test
    void afterPasswordFailsClosedToo() {
        when(mfa.status(eq("u9"), any())).thenThrow(new IllegalStateException("down"));
        assertEquals(503, statusOf(() -> flow.afterPassword("john", "u9", tokens())));
        verify(kc).logout("r1");
    }

    @Test
    void sendsUsersAccessTokenAsProofOnEveryCall() {
        String accessToken = (String) tokens().get("access_token");
        when(mfa.status("u1", accessToken)).thenReturn(new MfaServiceClient.Status(true, false));
        when(mfa.verify("u1", "123456", accessToken)).thenReturn(MfaResult.OK);

        String id = flow.login("john", "pw").challengeId();
        assertNotNull(flow.verify(id, "123456").get("access_token"));
    }

    @Test
    void lockedUserGets429() {
        when(mfa.status(eq("u1"), any())).thenReturn(new MfaServiceClient.Status(true, false));
        when(mfa.verify(eq("u1"), eq("111111"), any())).thenReturn(MfaResult.LOCKED);
        String id = flow.login("john", "pw").challengeId();
        assertEquals(429, statusOf(() -> flow.verify(id, "111111")));
        verify(kc).logout("r1");
    }
}
