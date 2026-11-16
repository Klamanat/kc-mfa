package com.ktb.kcmfa.starter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.ZSetOperations;

/** ทดสอบ logic ของ store กับ Redis จำลอง (Map) ไม่ได้ทดสอบกับ Redis จริง */
class RedisStoresTest {

    private final Map<String, String> kv = new HashMap<>();
    private final Map<String, Map<String, Double>> zsets = new HashMap<>();
    private StringRedisTemplate redis;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void fakeRedis() {
        redis = mock(StringRedisTemplate.class);
        ValueOperations<String, String> v = mock(ValueOperations.class);
        ZSetOperations<String, String> z = mock(ZSetOperations.class);
        when(redis.opsForValue()).thenReturn(v);
        when(redis.opsForZSet()).thenReturn(z);

        when(v.get(any())).thenAnswer(i -> kv.get((String) i.getArgument(0)));
        when(v.getAndDelete(anyString())).thenAnswer(i -> kv.remove((String) i.getArgument(0)));
        when(v.increment(anyString())).thenAnswer(i ->
                Long.parseLong(kv.merge(i.getArgument(0), "1", (a, b) -> String.valueOf(Long.parseLong(a) + 1))));
        org.mockito.Mockito.doAnswer(i -> kv.put(i.getArgument(0), i.getArgument(1)))
                .when(v).set(anyString(), anyString(), any(Duration.class));

        when(z.add(anyString(), anyString(), anyDouble())).thenAnswer(i -> {
            zsets.computeIfAbsent(i.getArgument(0), k -> new HashMap<>()).put(i.getArgument(1), i.getArgument(2));
            return true;
        });
        when(z.rangeByScore(anyString(), anyDouble(), anyDouble(), anyLong(), anyLong())).thenAnswer(i -> {
            Set<String> out = new LinkedHashSet<>();
            double max = i.getArgument(2);
            zsets.getOrDefault((String) i.getArgument(0), Map.of()).forEach((m, s) -> {
                if (s <= max) {
                    out.add(m);
                }
            });
            return out;
        });
        when(z.remove(anyString(), any(Object[].class))).thenAnswer(i -> {
            Map<String, Double> set = zsets.getOrDefault((String) i.getArgument(0), new HashMap<>());
            return set.remove(i.getArgument(1)) == null ? 0L : 1L;
        });

        when(redis.getExpire(anyString(), any(TimeUnit.class)))
                .thenAnswer(i -> kv.containsKey((String) i.getArgument(0)) ? 60_000L : -2L);
        when(redis.delete(anyCollection())).thenAnswer(i -> {
            long n = 0;
            for (Object k : (Collection<?>) i.getArgument(0)) {
                n += kv.remove(k) == null ? 0 : 1;
            }
            return n;
        });
    }

    @Test
    void challengeRoundTripsThroughJson() {
        RedisChallengeStore store = new RedisChallengeStore(redis, "kcmfa:web1:");
        Challenge c = store.create(Challenge.Type.ENROLL, "u1", "john",
                Map.of("access_token", "a", "refresh_token", "r1", "expires_in", 300), Duration.ofMinutes(5), true);

        Challenge back = store.find(c.id).orElseThrow();
        assertEquals(Challenge.Type.ENROLL, back.type);
        assertEquals("u1", back.userId);
        assertEquals("john", back.username);
        assertEquals("r1", back.tokens.get("refresh_token"));
        assertEquals(300, back.tokens.get("expires_in"));
        assertEquals(c.expiresAt.toEpochMilli(), back.expiresAt.toEpochMilli());
        assertTrue(back.external);
        assertTrue(kv.keySet().stream().allMatch(k -> k.startsWith("kcmfa:web1:")));
    }

    @Test
    void encryptedStoresKeepTokensOutOfRedisAndBindValueToItsKey() {
        PayloadCipher cipher = new PayloadCipher(java.util.Base64.getEncoder().encodeToString(new byte[32]));
        RedisChallengeStore store = new RedisChallengeStore(redis, "p:", cipher);
        Challenge c = store.create(Challenge.Type.VERIFY, "u1", "john",
                Map.of("access_token", "ACCESS-123", "refresh_token", "REFRESH-456"), Duration.ofMinutes(5), false);

        assertTrue(kv.values().stream().noneMatch(v -> v.contains("ACCESS-123") || v.contains("REFRESH-456")));
        assertEquals("REFRESH-456", store.find(c.id).orElseThrow().tokens.get("refresh_token"));

        // ค่าที่ถูกคัดลอกไปไว้ใต้ key ของ challenge อื่นต้องอ่านไม่ได้
        kv.put("p:ch:other", kv.get("p:ch:" + c.id));
        assertFalse(store.find("other").isPresent());

        RedisOAuthStateStore oauth = new RedisOAuthStateStore(redis, "p:", cipher);
        oauth.put("r:1", OAuthEntry.result(new LoginFlow.LoginResult("OK", null,
                Map.of("access_token", "OAUTH-ACCESS")), Instant.now().plusSeconds(60)));
        assertTrue(kv.values().stream().noneMatch(v -> v.contains("OAUTH-ACCESS")));
        assertEquals("OAUTH-ACCESS", oauth.take("r:1").orElseThrow().tokens.get("access_token"));
    }

    @Test
    void attemptsAreCountedInRedisAndGoneAfterRemove() {
        RedisChallengeStore store = new RedisChallengeStore(redis, "p:");
        Challenge c = store.create(Challenge.Type.VERIFY, "u1", "john", Map.of(), Duration.ofMinutes(5), false);

        assertEquals(1, store.incrementAttempts(c.id));
        assertEquals(2, store.incrementAttempts(c.id));
        store.remove(c.id);
        assertFalse(store.find(c.id).isPresent());
        assertEquals(0, store.incrementAttempts(c.id));
        assertEquals(0, store.incrementAttempts("unknown"));
        assertTrue(kv.isEmpty());
    }

    @Test
    void sweepReturnsExpiredChallengeOnceWithItsTokens() {
        RedisChallengeStore store = new RedisChallengeStore(redis, "p:");
        Challenge expired = store.create(Challenge.Type.VERIFY, "u1", "john",
                Map.of("refresh_token", "r1"), Duration.ofMillis(-1), false);
        Challenge live = store.create(Challenge.Type.VERIFY, "u2", "jane",
                Map.of("refresh_token", "r2"), Duration.ofMinutes(5), false);

        List<Challenge> swept = store.removeExpired();
        assertEquals(1, swept.size());
        assertEquals("r1", swept.get(0).tokens.get("refresh_token"));
        assertTrue(store.removeExpired().isEmpty());          // instance อื่นมาเก็บซ้ำไม่ได้
        assertFalse(store.find(expired.id).isPresent());
        assertTrue(store.find(live.id).isPresent());
    }

    @Test
    void removedChallengeIsNotSweptLater() {
        RedisChallengeStore store = new RedisChallengeStore(redis, "p:");
        Challenge c = store.create(Challenge.Type.VERIFY, "u1", "john",
                Map.of("refresh_token", "r1"), Duration.ofMillis(-1), false);
        store.remove(c.id);                                    // ผ่าน OTP แล้ว token ถูกปล่อยให้ user
        assertTrue(store.removeExpired().isEmpty());           // ต้องไม่ถูก revoke ทีหลัง
    }

    @Test
    void oauthEntryIsTakenOnlyOnce() {
        RedisOAuthStateStore store = new RedisOAuthStateStore(redis, "p:");
        store.put("s:abc", OAuthEntry.authRequest("bind", "verifier", "nonce", Instant.now().plusSeconds(300)));

        OAuthEntry e = store.take("s:abc").orElseThrow();
        assertEquals(OAuthEntry.Kind.AUTH_REQUEST, e.kind);
        assertEquals("bind", e.binding);
        assertEquals("verifier", e.codeVerifier);
        assertEquals("nonce", e.nonce);
        assertNull(e.tokens);
        assertFalse(store.take("s:abc").isPresent());
        assertFalse(store.take(null).isPresent());
    }

    @Test
    void sweepReturnsOnlyUncollectedResultsThatHoldTokens() {
        RedisOAuthStateStore store = new RedisOAuthStateStore(redis, "p:");
        Instant past = Instant.now().minusSeconds(1);
        store.put("r:ok", OAuthEntry.result(new LoginFlow.LoginResult("OK", null, Map.of("refresh_token", "r1")), past));
        store.put("r:taken", OAuthEntry.result(new LoginFlow.LoginResult("OK", null, Map.of("refresh_token", "r2")), past));
        store.put("r:mfa", OAuthEntry.result(new LoginFlow.LoginResult("MFA_REQUIRED", "ch1", null), past));
        store.put("s:old", OAuthEntry.authRequest("b", "v", "n", past));

        assertEquals("r2", store.take("r:taken").orElseThrow().tokens.get("refresh_token"));

        List<OAuthEntry> swept = store.removeExpired();
        assertEquals(1, swept.size());
        assertEquals("r1", swept.get(0).tokens.get("refresh_token"));
        assertTrue(store.removeExpired().isEmpty());
    }
}
