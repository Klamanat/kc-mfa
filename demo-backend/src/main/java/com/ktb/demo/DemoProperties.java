package com.ktb.demo;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * demo.cookie-secure  ค่าเริ่มต้น true (cookie ส่งผ่าน HTTPS เท่านั้น) ตั้ง false เฉพาะตอนลองบน http://localhost ด้วยตัวเอง
 *                      (Chrome/Firefox รับ Secure cookie บน localhost ได้อยู่แล้ว แต่ Safari ไม่รับ)
 * demo.rate-limit     จำนวนครั้งต่อ IP ต่อหน้าต่างเวลา (แยกกลุ่ม login กับ otp)
 */
@ConfigurationProperties(prefix = "demo")
public record DemoProperties(@DefaultValue("true") boolean cookieSecure,
                             @DefaultValue("10") int rateLimit,
                             @DefaultValue("1m") Duration rateWindow) {}
