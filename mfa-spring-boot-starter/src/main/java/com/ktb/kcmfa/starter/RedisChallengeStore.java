package com.ktb.kcmfa.starter;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.StringRedisTemplate;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * ChallengeStore บน Redis สำหรับเว็บที่รันหลาย instance (kcmfa.store=redis)
 *
 *   {prefix}ch:{id}      JSON ของ challenge   TTL = อายุ challenge + GRACE
 *   {prefix}ch:{id}:n    ตัวนับครั้งที่กรอกผิด (INCR จึง atomic ข้าม instance)
 *   {prefix}ch-exp       sorted set: id -> เวลาหมดอายุ ใช้หา challenge ที่หมดอายุเพื่อ revoke session
 *
 * key มีอายุยาวกว่า challenge เล็กน้อย เพื่อให้ตัวเก็บกวาดยังอ่าน token ไป revoke ได้หลังหมดอายุ
 * (LoginFlow ตรวจ expiresAt เองทุกครั้ง challenge ที่หมดอายุแล้วจึงใช้ไม่ได้แม้ key ยังอยู่)
 * instance ที่ ZREM สำเร็จเท่านั้นที่ได้ challenge ไป จึง revoke ไม่ซ้ำกัน
 *
 * token ของ user ถูกเก็บใน Redis ระหว่างรอ OTP: Redis ต้องเปิด auth + TLS และไม่ใช้ร่วมกับระบบที่ไม่เกี่ยวข้อง
 */
public class RedisChallengeStore implements ChallengeStore {

    /** DTO สำหรับ JSON (public เพื่อให้ Jackson เข้าถึงได้) */
    public record Dto(String id, Challenge.Type type, String userId, String username,
                      Map<String, Object> tokens, long expiresAtMs, boolean external) {}

    static final Duration GRACE = Duration.ofMinutes(10);
    private static final int SWEEP_BATCH = 500;
    private static final ObjectMapper JSON = new ObjectMapper();

    private final StringRedisTemplate redis;
    private final String prefix;
    private final SecureRandom random = new SecureRandom();

    public RedisChallengeStore(StringRedisTemplate redis, String prefix) {
        this.redis = redis;
        this.prefix = prefix;
    }

    @Override
    public Challenge create(Challenge.Type type, String userId, String username,
                            Map<String, Object> tokens, Duration ttl, boolean external) {
        byte[] b = new byte[32];
        random.nextBytes(b);
        String id = Base64.getUrlEncoder().withoutPadding().encodeToString(b);
        Challenge c = new Challenge(id, type, userId, username, tokens, Instant.now().plus(ttl), external);
        Duration life = (ttl.isNegative() ? Duration.ZERO : ttl).plus(GRACE);
        redis.opsForValue().set(key(id), write(c), life);
        redis.opsForZSet().add(expiryKey(), id, c.expiresAt.toEpochMilli());
        return c;
    }

    @Override
    public Optional<Challenge> find(String id) {
        return id == null ? Optional.empty() : Optional.ofNullable(read(redis.opsForValue().get(key(id))));
    }

    @Override
    public int incrementAttempts(String id) {
        if (id == null) {
            return 0;
        }
        Long life = redis.getExpire(key(id), TimeUnit.MILLISECONDS);
        if (life == null || life <= 0) {
            return 0;   // challenge ไม่อยู่แล้ว
        }
        Long n = redis.opsForValue().increment(counterKey(id));
        if (n == null) {
            return 0;
        }
        if (n == 1) {
            redis.expire(counterKey(id), Duration.ofMillis(life));
        }
        return (int) Math.min(n, Integer.MAX_VALUE);
    }

    @Override
    public void remove(String id) {
        if (id == null) {
            return;
        }
        redis.delete(List.of(key(id), counterKey(id)));
        redis.opsForZSet().remove(expiryKey(), id);
    }

    @Override
    public List<Challenge> removeExpired() {
        List<Challenge> expired = new ArrayList<>();
        Set<String> ids = redis.opsForZSet().rangeByScore(expiryKey(), 0, Instant.now().toEpochMilli(), 0, SWEEP_BATCH);
        if (ids == null) {
            return expired;
        }
        for (String id : ids) {
            Long won = redis.opsForZSet().remove(expiryKey(), id);
            if (won == null || won == 0) {
                continue;   // instance อื่นหยิบไปแล้ว หรือถูก remove() ไปก่อน
            }
            Challenge c = read(redis.opsForValue().get(key(id)));
            redis.delete(List.of(key(id), counterKey(id)));
            if (c != null) {
                expired.add(c);
            }
        }
        return expired;
    }

    private String key(String id) {
        return prefix + "ch:" + id;
    }

    private String counterKey(String id) {
        return key(id) + ":n";
    }

    private String expiryKey() {
        return prefix + "ch-exp";
    }

    private static String write(Challenge c) {
        try {
            return JSON.writeValueAsString(new Dto(c.id, c.type, c.userId, c.username, c.tokens,
                    c.expiresAt.toEpochMilli(), c.external));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Cannot serialize challenge", e);
        }
    }

    private static Challenge read(String json) {
        if (json == null) {
            return null;
        }
        try {
            Dto d = JSON.readValue(json, Dto.class);
            return new Challenge(d.id(), d.type(), d.userId(), d.username(), d.tokens(),
                    Instant.ofEpochMilli(d.expiresAtMs()), d.external());
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Cannot read challenge", e);
        }
    }
}
