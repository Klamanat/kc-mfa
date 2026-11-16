package com.ktb.kcmfa.starter;

import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;

/**
 * เก็บกวาด challenge ที่หมดอายุเป็นรอบ (kcmfa.sweep-interval) ใน thread แยก
 * และ revoke session ที่ผู้ออก token (Keycloak หรือ OAuth provider ภายนอก) ของ challenge เหล่านั้น จึงไม่เพิ่มภาระให้ request ของ login
 * ถ้าใช้ ChallengeStore แบบมี TTL ในตัว (เช่น Redis) removeExpired() จะคืน list ว่าง ตัวนี้จึงไม่ทำอะไร
 */
public class ChallengeSweeper implements InitializingBean, DisposableBean {

    private final ChallengeStore store;
    private final SessionRevoker revoker;
    private final Duration interval;
    private ScheduledExecutorService executor;

    private final Runnable extra;

    public ChallengeSweeper(ChallengeStore store, KeycloakClient keycloak, Duration interval) {
        this(store, new SessionRevoker(keycloak, null), interval, () -> {});
    }

    /** @param extra งานเก็บกวาดอื่นที่ใช้รอบเดียวกัน (เช่น OAuthLoginFlow.sweepExpired) */
    public ChallengeSweeper(ChallengeStore store, SessionRevoker revoker, Duration interval, Runnable extra) {
        this.store = store;
        this.revoker = revoker;
        this.interval = interval;
        this.extra = extra;
    }

    /** เรียกตรงๆ ได้ (ใช้ในเทสต์) */
    public void sweepOnce() {
        for (Challenge c : store.removeExpired()) {
            revoker.revoke(c.tokens, c.external);
        }
        extra.run();
    }

    @Override
    public void afterPropertiesSet() {
        executor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "kcmfa-challenge-sweeper");
            t.setDaemon(true);
            return t;
        });
        long ms = Math.max(1000, interval.toMillis());
        executor.scheduleWithFixedDelay(this::safeSweep, ms, ms, TimeUnit.MILLISECONDS);
    }

    @Override
    public void destroy() {
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    private void safeSweep() {
        try {
            sweepOnce();
        } catch (RuntimeException ignored) {
            // ห้ามให้ exception ทำให้ schedule หยุด
        }
    }
}
