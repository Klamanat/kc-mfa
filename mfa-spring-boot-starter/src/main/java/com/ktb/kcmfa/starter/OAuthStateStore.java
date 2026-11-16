package com.ktb.kcmfa.starter;

import java.util.List;
import java.util.Optional;

/**
 * ที่เก็บสถานะของ OAuth login เริ่มต้นเป็น in-memory (instance เดียว)
 * ถ้าเว็บรันหลาย instance ให้ประกาศ bean ของ OAuthStateStore เองเป็น Redis (TTL = entry.expiresAt)
 */
public interface OAuthStateStore {

    void put(String key, OAuthEntry entry);

    /** อ่านแล้วลบในขั้นตอนเดียว (atomic) เพื่อให้ state / ผล login ใช้ได้ครั้งเดียว */
    Optional<OAuthEntry> take(String key);

    /** ลบรายการที่หมดอายุและคืนให้ผู้เรียก revoke session (store ที่ใช้ TTL คืน list ว่างได้) */
    List<OAuthEntry> removeExpired();
}
