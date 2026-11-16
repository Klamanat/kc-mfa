package com.ktb.kcmfa.starter;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * ที่เก็บ challenge เริ่มต้นเป็น in-memory (instance เดียว)
 * ถ้าเว็บรันหลาย instance ให้ตั้ง kcmfa.store=redis (ดู RedisChallengeStore) หรือประกาศ bean ของ ChallengeStore เอง
 */
public interface ChallengeStore {

    /** @param external true ถ้า tokens มาจาก OAuth provider ภายนอก (มีผลกับปลายทางที่ใช้ revoke) */
    Challenge create(Challenge.Type type, String userId, String username, Map<String, Object> tokens, Duration ttl,
                     boolean external);

    Optional<Challenge> find(String id);

    /**
     * นับการกรอกรหัสผิดของ challenge เพิ่ม 1 แบบ atomic (request พร้อมกันหรือคนละ instance ต้องไม่นับหาย)
     * @return จำนวนครั้งที่ผิดรวมครั้งนี้ หรือ 0 ถ้า challenge ไม่อยู่แล้ว
     */
    int incrementAttempts(String id);

    void remove(String id);

    /** ลบ challenge ที่หมดอายุแล้วและคืนรายการให้ผู้เรียก revoke session ที่ Keycloak (store ที่ใช้ TTL คืน list ว่างได้) */
    List<Challenge> removeExpired();
}
