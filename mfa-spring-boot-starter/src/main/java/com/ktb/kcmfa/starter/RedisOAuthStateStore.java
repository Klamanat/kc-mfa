package com.ktb.kcmfa.starter;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.springframework.data.redis.core.StringRedisTemplate;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * OAuthStateStore บน Redis สำหรับเว็บที่รันหลาย instance (kcmfa.store=redis) ต้องใช้ Redis 6.2+ (คำสั่ง GETDEL)
 *
 *   {prefix}oa:{key}   JSON ของ entry   TTL = อายุ entry + GRACE
 *   {prefix}oa-exp     sorted set ของ entry ที่ถือ token อยู่ (ผล login สถานะ OK) ใช้ revoke เมื่อไม่มีใครมารับ
 *
 * take() ใช้ GETDEL จึงได้ค่าครั้งเดียวแม้ request มาพร้อมกันคนละ instance
 */
public class RedisOAuthStateStore implements OAuthStateStore {

    /** DTO สำหรับ JSON (public เพื่อให้ Jackson เข้าถึงได้) */
    public record Dto(OAuthEntry.Kind kind, long expiresAtMs, String binding, String codeVerifier, String nonce,
                      String status, String challengeId, Map<String, Object> tokens) {}

    private static final int SWEEP_BATCH = 500;
    private static final ObjectMapper JSON = new ObjectMapper();

    private final StringRedisTemplate redis;
    private final String prefix;
    private final PayloadCipher cipher;      // null = ข้อความล้วน (ดู RedisChallengeStore)

    public RedisOAuthStateStore(StringRedisTemplate redis, String prefix) {
        this(redis, prefix, null);
    }

    public RedisOAuthStateStore(StringRedisTemplate redis, String prefix, PayloadCipher cipher) {
        this.redis = redis;
        this.prefix = prefix;
        this.cipher = cipher;
    }

    @Override
    public void put(String key, OAuthEntry entry) {
        Duration left = Duration.between(Instant.now(), entry.expiresAt);
        Duration life = left.isNegative() ? Duration.ZERO : left;
        // เผื่อเวลาให้ตัวเก็บกวาดเฉพาะ entry ที่ถือ token (ต้องอ่านไป revoke) entry อื่นหมดอายุตามจริง
        // เพราะ GET oauth/login ไม่ต้อง login ก่อน จึงไม่ควรค้างใน Redis นานเกินจำเป็น
        life = entry.tokens != null ? life.plus(RedisChallengeStore.GRACE) : life.plusSeconds(1);
        redis.opsForValue().set(key(key), seal(key(key), write(entry)), life);
        if (entry.tokens != null) {
            redis.opsForZSet().add(expiryKey(), key, entry.expiresAt.toEpochMilli());
        }
    }

    @Override
    public Optional<OAuthEntry> take(String key) {
        if (key == null) {
            return Optional.empty();
        }
        OAuthEntry e = read(open(key(key), redis.opsForValue().getAndDelete(key(key))));
        if (e != null && e.tokens != null) {
            redis.opsForZSet().remove(expiryKey(), key);
        }
        return Optional.ofNullable(e);
    }

    @Override
    public List<OAuthEntry> removeExpired() {
        List<OAuthEntry> expired = new ArrayList<>();
        Set<String> keys = redis.opsForZSet().rangeByScore(expiryKey(), 0, Instant.now().toEpochMilli(), 0, SWEEP_BATCH);
        if (keys == null) {
            return expired;
        }
        for (String k : keys) {
            Long won = redis.opsForZSet().remove(expiryKey(), k);
            if (won == null || won == 0) {
                continue;   // instance อื่นหยิบไปแล้ว หรือถูก take() ไปก่อน
            }
            OAuthEntry e = read(open(key(k), redis.opsForValue().getAndDelete(key(k))));
            if (e != null) {
                expired.add(e);
            }
        }
        return expired;
    }

    private String seal(String redisKey, String json) {
        return cipher == null ? json : cipher.encrypt(json, redisKey);
    }

    private String open(String redisKey, String stored) {
        return cipher == null || stored == null ? stored : cipher.decrypt(stored, redisKey);
    }

    private String key(String key) {
        return prefix + "oa:" + key;
    }

    private String expiryKey() {
        return prefix + "oa-exp";
    }

    private static String write(OAuthEntry e) {
        try {
            return JSON.writeValueAsString(new Dto(e.kind, e.expiresAt.toEpochMilli(), e.binding, e.codeVerifier,
                    e.nonce, e.status, e.challengeId, e.tokens));
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Cannot serialize OAuth entry", ex);
        }
    }

    private static OAuthEntry read(String json) {
        if (json == null) {
            return null;
        }
        try {
            Dto d = JSON.readValue(json, Dto.class);
            return new OAuthEntry(d.kind(), Instant.ofEpochMilli(d.expiresAtMs()), d.binding(), d.codeVerifier(),
                    d.nonce(), d.status(), d.challengeId(), d.tokens());
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Cannot read OAuth entry", ex);
        }
    }
}
