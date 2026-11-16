package com.ktb.demo;

import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

/**
 * fixed-window ต่อ key ในหน่วยความจำ (instance เดียวเท่านั้น)
 * หลาย instance ให้ย้ายไป gateway / Redis แทน
 */
@Component
public class RateLimiter {

    private record Window(long start, int count) {}

    private final ConcurrentHashMap<String, Window> windows = new ConcurrentHashMap<>();
    private final int limit;
    private final long windowMillis;

    public RateLimiter(DemoProperties props) {
        this.limit = props.rateLimit();
        this.windowMillis = props.rateWindow().toMillis();
    }

    public boolean tryAcquire(String key) {
        long now = System.currentTimeMillis();
        if (windows.size() > 10_000) {               // กัน map โตไม่จำกัดเมื่อโดนยิงจากหลาย IP
            windows.values().removeIf(w -> now - w.start() >= windowMillis);
        }
        boolean[] ok = {false};
        windows.compute(key, (k, w) -> {
            if (w == null || now - w.start() >= windowMillis) {
                ok[0] = true;
                return new Window(now, 1);
            }
            if (w.count() < limit) {
                ok[0] = true;
                return new Window(w.start(), w.count() + 1);
            }
            return w;
        });
        return ok[0];
    }
}
