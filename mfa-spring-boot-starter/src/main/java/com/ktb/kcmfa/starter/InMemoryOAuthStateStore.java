package com.ktb.kcmfa.starter;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryOAuthStateStore implements OAuthStateStore {

    private final ConcurrentHashMap<String, OAuthEntry> map = new ConcurrentHashMap<>();

    @Override
    public void put(String key, OAuthEntry entry) {
        map.put(key, entry);
    }

    @Override
    public Optional<OAuthEntry> take(String key) {
        return key == null ? Optional.empty() : Optional.ofNullable(map.remove(key));
    }

    @Override
    public List<OAuthEntry> removeExpired() {
        Instant now = Instant.now();
        List<OAuthEntry> expired = new ArrayList<>();
        for (Map.Entry<String, OAuthEntry> e : map.entrySet()) {
            if (e.getValue().expiresAt.isBefore(now) && map.remove(e.getKey(), e.getValue())) {
                expired.add(e.getValue());
            }
        }
        return expired;
    }
}
