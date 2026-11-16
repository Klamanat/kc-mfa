package com.ktb.mfa;

import java.time.Instant;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/** ลบ pending ที่หมดอายุเป็นรอบ ไม่ให้ตารางโตจากคนที่เปิดหน้า QR แล้วไม่ยืนยัน (หลาย instance รันซ้ำกันได้ ไม่มีผลเสีย) */
@Component
public class PendingCleanup {

    private final MfaPendingRepository pendingRepo;

    public PendingCleanup(MfaPendingRepository pendingRepo) {
        this.pendingRepo = pendingRepo;
    }

    @Scheduled(fixedDelayString = "PT10M", initialDelayString = "PT1M")
    @Transactional
    public void run() {
        pendingRepo.deleteExpired(Instant.now());
    }
}
