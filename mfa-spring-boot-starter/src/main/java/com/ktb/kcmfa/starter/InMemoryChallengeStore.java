package com.ktb.kcmfa.starter;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryChallengeStore implements ChallengeStore {

    private final SecureRandom random = new SecureRandom();
    private final ConcurrentHashMap<String, Challenge> map = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Integer> attempts = new ConcurrentHashMap<>();

    @Override
    public Challenge create(Challenge.Type type, String userId, String username,
                            Map<String, Object> tokens, Duration ttl, boolean external) {
        byte[] b = new byte[32];
        random.nextBytes(b);
        String id = Base64.getUrlEncoder().withoutPadding().encodeToString(b);
        Challenge c = new Challenge(id, type, userId, username, tokens, Instant.now().plus(ttl), external);
        map.put(id, c);
        return c;
    }

    @Override
    public Optional<Challenge> find(String id) {
        return id == null ? Optional.empty() : Optional.ofNullable(map.get(id));
    }

    @Override
    public int incrementAttempts(String id) {
        if (id == null || !map.containsKey(id)) {
            return 0;
        }
        return attempts.merge(id, 1, Integer::sum);
    }

    @Override
    public void remove(String id) {
        map.remove(id);
        attempts.remove(id);
    }

    @Override
    public List<Challenge> removeExpired() {
        Instant now = Instant.now();
        List<Challenge> expired = new ArrayList<>();
        for (Challenge c : map.values()) {
            if (c.expiresAt.isBefore(now) && map.remove(c.id, c)) {
                attempts.remove(c.id);
                expired.add(c);
            }
        }
        return expired;
    }
}
