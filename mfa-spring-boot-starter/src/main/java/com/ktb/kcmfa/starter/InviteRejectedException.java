package com.ktb.kcmfa.starter;

/** MFA service ไม่รับรหัสเชิญ (ผิด หมดอายุ ใช้ไปแล้ว หรือถูกเดาเกินจำนวนครั้ง) */
public class InviteRejectedException extends RuntimeException {

    public InviteRejectedException(Throwable cause) {
        super("Invite code rejected", cause);
    }
}
