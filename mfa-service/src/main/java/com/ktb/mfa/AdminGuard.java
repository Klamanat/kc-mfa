package com.ktb.mfa;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

/**
 * ด่านของ endpoint ที่ใช้สิทธิ์ admin (ออกรหัสเชิญ / reset MFA) นอกจาก token ของ client ที่ admin: true แล้วต้องผ่านอีก 3 ข้อ:
 *   1. เรียกจาก IP ที่อยู่ใน mfa.admin.allowed-cidrs (ไม่ตั้ง = ปฏิเสธทั้งหมด) secret ที่รั่วไปใช้จากเครื่องอื่นไม่ได้
 *   2. ต้องแจ้งผู้ดูแลใน header X-Admin-Actor เพื่อให้ audit log รู้ว่าใครสั่ง (ผู้เรียกระบุเอง ไม่ได้พิสูจน์ตัวตน
 *      client secret ตัวเดียวแยกคนไม่ได้ ถ้าต้องการพิสูจน์รายคนต้องให้ผู้ดูแลแต่ละคนมี service account ของตัวเอง)
 *   3. ไม่เกิน mfa.admin.max-per-hour ครั้งต่อ client ต่อชนิดเหตุการณ์ในช่วง 1 ชั่วโมงที่ผ่านมา (นับจาก audit log)
 */
@Component
public class AdminGuard {

    public static final String ACTOR_HEADER = "X-Admin-Actor";

    private static final Logger LOG = LoggerFactory.getLogger("mfa.audit");
    private static final Pattern ACTOR = Pattern.compile("[A-Za-z0-9@._-]{1,64}");

    private final AdminProps props;
    private final AuditService audit;
    private final List<IpAddressMatcher> allowed;

    public AdminGuard(AdminProps props, AuditService audit) {
        this.props = props;
        this.audit = audit;
        // CIDR ที่เขียนผิดทำให้ service start ไม่ขึ้น (ดีกว่าเปิดกว้างโดยไม่รู้ตัว)
        this.allowed = props.allowedCidrs().stream().map(IpAddressMatcher::new).toList();
    }

    /** @return ข้อมูลผู้กระทำสำหรับ audit; throw ResponseStatusException ถ้าไม่ผ่านข้อใดข้อหนึ่ง */
    public AuditService.Ctx check(MfaProps.Client client, String actor, String ip, String event) {
        if (!client.admin()) {
            LOG.warn("admin-denied reason=not-admin client={} ip={} event={}", client.clientId(), ip, event);
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Admin client required");
        }
        if (!allowedIp(ip)) {
            LOG.warn("admin-denied reason=ip client={} ip={} event={}", client.clientId(), ip, event);
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Admin calls are not allowed from this address");
        }
        if (actor == null || !ACTOR.matcher(actor).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    ACTOR_HEADER + " header is required (1-64 chars: letters, digits, @ . _ -)");
        }
        long recent = audit.countSince(event, client.clientId(), Instant.now().minus(Duration.ofHours(1)));
        if (recent >= props.maxPerHour()) {
            LOG.warn("admin-denied reason=rate client={} actor={} ip={} event={} lastHour={}",
                    client.clientId(), actor, ip, event, recent);
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Admin rate limit reached");
        }
        return new AuditService.Ctx(client.clientId(), actor, ip);
    }

    private boolean allowedIp(String ip) {
        if (ip == null) {
            return false;
        }
        for (IpAddressMatcher m : allowed) {
            if (m.matches(ip)) {
                return true;
            }
        }
        return false;
    }
}
