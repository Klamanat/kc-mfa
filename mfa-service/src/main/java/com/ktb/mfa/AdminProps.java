package com.ktb.mfa;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * mfa.admin.allowed-cidrs  IP/CIDR ที่ endpoint ของ admin (ออกรหัสเชิญ / reset) เรียกได้ เช่น ["10.20.0.0/16"]
 *                          เว้นว่าง = ปิด endpoint ของ admin ทั้งหมด (ปฏิเสธทุก request)
 *                          ใช้ IP ที่ service เห็น (remote address) หลัง reverse proxy ต้องตั้ง server.forward-headers-strategy
 *                          และมั่นใจว่า proxy เป็นด่านเดียวที่เข้าถึง service ได้ ไม่งั้น header ถูกปลอมได้
 * mfa.admin.max-per-hour   จำนวนครั้งต่อ admin client ต่อชั่วโมง แยกตามชนิดเหตุการณ์ (ออกรหัสเชิญ / reset)
 *                          จำกัดความเสียหายและทำให้การใช้ secret ที่รั่วเห็นได้ใน audit log
 */
@ConfigurationProperties(prefix = "mfa.admin")
public record AdminProps(List<String> allowedCidrs, @DefaultValue("20") int maxPerHour) {

    public AdminProps {
        allowedCidrs = allowedCidrs == null ? List.of() : List.copyOf(allowedCidrs);
    }
}
