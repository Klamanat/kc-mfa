package com.ktb.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class AdminGuardTest {

    private static final String EVENT = "INVITE_ISSUED";

    private final AuditService audit = mock(AuditService.class);
    private final MfaProps.Client admin =
            new MfaProps.Client("brand-a", "mfa-admin", false, null, null, null, null, true);
    private final MfaProps.Client web =
            new MfaProps.Client("brand-a", "web1-backend", true, "Brand A", null, null, null, false);

    private AdminGuard guard(List<String> cidrs, int maxPerHour) {
        return new AdminGuard(new AdminProps(cidrs, maxPerHour), audit);
    }

    private static int status(Runnable r) {
        return assertThrows(ResponseStatusException.class, r::run).getStatusCode().value();
    }

    @Test
    void allowsAdminFromAllowedAddressWithActor() {
        AuditService.Ctx ctx = guard(List.of("10.20.0.0/16"), 20).check(admin, "somchai@ktb", "10.20.3.4", EVENT);
        assertEquals("mfa-admin", ctx.clientId());
        assertEquals("somchai@ktb", ctx.actor());
        assertEquals("10.20.3.4", ctx.ip());
    }

    @Test
    void rejectsNonAdminClient() {
        assertEquals(403, status(() -> guard(List.of("10.20.0.0/16"), 20).check(web, "a", "10.20.3.4", EVENT)));
    }

    @Test
    void rejectsAddressOutsideAllowListAndDeniesEverythingWhenListIsEmpty() {
        assertEquals(403, status(() -> guard(List.of("10.20.0.0/16"), 20).check(admin, "a", "203.0.113.9", EVENT)));
        assertEquals(403, status(() -> guard(List.of(), 20).check(admin, "a", "10.20.3.4", EVENT)));
        assertEquals(403, status(() -> guard(List.of("10.20.0.0/16"), 20).check(admin, "a", null, EVENT)));
    }

    @Test
    void requiresAWellFormedActor() {
        AdminGuard g = guard(List.of("10.20.0.0/16"), 20);
        assertEquals(400, status(() -> g.check(admin, null, "10.20.3.4", EVENT)));
        assertEquals(400, status(() -> g.check(admin, "", "10.20.3.4", EVENT)));
        assertEquals(400, status(() -> g.check(admin, "x\ny=forged", "10.20.3.4", EVENT)));   // กัน log injection
        assertEquals(400, status(() -> g.check(admin, "a".repeat(65), "10.20.3.4", EVENT)));
    }

    @Test
    void limitsAdminActionsPerHour() {
        when(audit.countSince(eq(EVENT), eq("mfa-admin"), any(Instant.class))).thenReturn(20L);
        assertEquals(429, status(() -> guard(List.of("10.20.0.0/16"), 20).check(admin, "a", "10.20.3.4", EVENT)));
        when(audit.countSince(eq(EVENT), eq("mfa-admin"), any(Instant.class))).thenReturn(19L);
        assertEquals("a", guard(List.of("10.20.0.0/16"), 20).check(admin, "a", "10.20.3.4", EVENT).actor());
    }

    @Test
    void badCidrFailsStartup() {
        assertThrows(IllegalArgumentException.class, () -> guard(List.of("10.0.0.0/abc"), 20));   // prefix ไม่ใช่ตัวเลข (ไม่ใช้ชื่อโฮสต์ จะได้ไม่ต้อง resolve DNS)
    }

    @Test
    void inviteIsRequiredByDefaultWhenMfaIsEnforcedButCanBeOptedOut() {
        assertTrue(web.requiresInvite());                                                        // enforce=true, ไม่ตั้ง
        assertFalse(new MfaProps.Client("r", "c", false, null, null, null, null, false).requiresInvite());
        assertFalse(new MfaProps.Client("r", "c", true, null, null, null, false, false).requiresInvite());
        assertTrue(new MfaProps.Client("r", "c", false, null, null, null, true, false).requiresInvite());
    }
}
