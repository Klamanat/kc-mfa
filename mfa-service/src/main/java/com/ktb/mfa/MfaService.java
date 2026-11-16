package com.ktb.mfa;

import java.time.Instant;
import java.util.Optional;
import java.util.OptionalLong;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class MfaService {

    public enum Result { OK, BAD_CODE, LOCKED, NOT_ENROLLED, NO_PENDING, ALREADY_ENROLLED }

    public record EnrollStart(String secret, String otpauthUri) {}

    private final MfaCredentialRepository repo;
    private final MfaPendingRepository pendingRepo;
    private final TotpService totp;
    private final SecretCrypto crypto;
    private final MfaProps props;

    public MfaService(MfaCredentialRepository repo, MfaPendingRepository pendingRepo,
                      TotpService totp, SecretCrypto crypto, MfaProps props) {
        this.repo = repo;
        this.pendingRepo = pendingRepo;
        this.totp = totp;
        this.crypto = crypto;
        this.props = props;
    }

    public boolean isEnrolled(String realm, String userId) {
        return repo.existsById(MfaCredential.key(realm, userId));
    }

    /**
     * ตรวจ OTP ตอน login: มี lockout ต่อ user และกัน replay
     * ล็อกแถวของ user ไว้ทั้ง transaction เพื่อให้ request ที่ยิงพร้อมกันถูกตรวจทีละตัว
     */
    @Transactional
    public Result verify(String realm, String userId, String code) {
        String id = MfaCredential.key(realm, userId);
        MfaCredential cred = repo.findByIdForUpdate(id).orElse(null);
        if (cred == null) {
            return Result.NOT_ENROLLED;
        }
        Instant now = Instant.now();
        if (cred.getLockedUntil() != null && cred.getLockedUntil().isAfter(now)) {
            return Result.LOCKED;
        }

        OptionalLong step = totp.match(crypto.decrypt(cred.getSecretEnc(), id), code);
        if (step.isEmpty() || step.getAsLong() <= cred.getLastUsedStep()) {
            int failed = cred.getFailedAttempts() + 1;
            cred.setFailedAttempts(failed);
            if (failed >= props.lockAfterFailures()) {
                cred.setLockedUntil(now.plus(props.lockDuration()));
                cred.setFailedAttempts(0);
            }
            repo.save(cred);
            return Result.BAD_CODE;
        }

        cred.setLastUsedStep(step.getAsLong());
        cred.setFailedAttempts(0);
        cred.setLockedUntil(null);
        repo.save(cred);
        return Result.OK;
    }

    /**
     * เริ่ม enroll: สร้าง secret ใหม่เก็บเป็น pending
     * ปฏิเสธถ้า user มี MFA อยู่แล้ว (กันผู้ที่รู้รหัสผ่านมาเขียนทับ MFA เดิม)
     */
    @Transactional
    public Optional<EnrollStart> startEnrollment(String realm, String userId, String issuerLabel, String accountName) {
        String id = MfaCredential.key(realm, userId);
        if (repo.existsById(id)) {
            return Optional.empty();
        }
        byte[] secret = totp.newSecret();
        pendingRepo.save(new MfaPending(id, crypto.encrypt(secret, id), Instant.now().plus(props.enrollTtl())));
        return Optional.of(new EnrollStart(totp.toBase32(secret), totp.otpauthUri(issuerLabel, accountName, secret)));
    }

    /** ยืนยันโค้ดแรก แล้วเปลี่ยน pending ให้เป็น MFA จริง */
    @Transactional
    public Result confirmEnrollment(String realm, String userId, String code) {
        String id = MfaCredential.key(realm, userId);
        // ล็อก pending ก่อน แล้วค่อยเช็กว่ามี MFA แล้วหรือยัง: request ที่มาพร้อมกันจะเห็นผลของตัวแรกเสมอ
        MfaPending pending = pendingRepo.findByIdForUpdate(id).orElse(null);
        if (repo.existsById(id)) {
            return Result.ALREADY_ENROLLED;
        }
        if (pending == null) {
            return Result.NO_PENDING;
        }
        if (pending.getExpiresAt().isBefore(Instant.now())) {
            pendingRepo.delete(pending);
            return Result.NO_PENDING;
        }

        byte[] secret = crypto.decrypt(pending.getSecretEnc(), id);
        OptionalLong step = totp.match(secret, code);
        if (step.isEmpty()) {
            pending.setAttempts(pending.getAttempts() + 1);
            if (pending.getAttempts() >= props.lockAfterFailures()) {
                pendingRepo.delete(pending);   // ต้อง start ใหม่ (ได้ secret ใหม่)
            } else {
                pendingRepo.save(pending);
            }
            return Result.BAD_CODE;
        }

        repo.save(new MfaCredential(realm, userId, crypto.encrypt(secret, id), step.getAsLong()));
        pendingRepo.delete(pending);
        return Result.OK;
    }

    /** reset MFA (เช่น admin กดให้ user ที่ทำเครื่องหาย) ยังไม่เปิดเป็น endpoint โดยตั้งใจ */
    @Transactional
    public void reset(String realm, String userId) {
        repo.deleteById(MfaCredential.key(realm, userId));
        pendingRepo.deleteById(MfaCredential.key(realm, userId));
    }
}
