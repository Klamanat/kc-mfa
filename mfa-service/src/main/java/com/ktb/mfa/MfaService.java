package com.ktb.mfa;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Optional;
import java.util.OptionalLong;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class MfaService {

    public enum Result { OK, BAD_CODE, LOCKED, NOT_ENROLLED, NO_PENDING, ALREADY_ENROLLED }

    public record EnrollStart(String secret, String otpauthUri) {}

    public enum StartStatus { OK, ALREADY_ENROLLED, INVITE_INVALID }

    public record StartOutcome(StartStatus status, EnrollStart start) {}

    public record Invite(String code, Instant expiresAt) {}

    /** รหัสเชิญกรอกผิดได้กี่ครั้งก่อนถูกยกเลิก (ต้องให้ admin ออกใหม่) */
    static final int INVITE_MAX_ATTEMPTS = 5;
    // ตัดตัวที่สับสนง่าย (0/O, 1/I/L) เหลือ 31 ตัว x 10 ตำแหน่ง ~ 49 บิต
    private static final String INVITE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    private static final int INVITE_LENGTH = 10;

    private final MfaCredentialRepository repo;
    private final MfaPendingRepository pendingRepo;
    private final MfaInviteRepository inviteRepo;
    private final AuditService audit;
    private final TotpService totp;
    private final SecretCrypto crypto;
    private final MfaProps props;
    private final Duration inviteTtl;
    private final SecureRandom random = new SecureRandom();

    public MfaService(MfaCredentialRepository repo, MfaPendingRepository pendingRepo, MfaInviteRepository inviteRepo,
                      AuditService audit, TotpService totp, SecretCrypto crypto, MfaProps props,
                      @Value("${mfa.invite-ttl:30m}") Duration inviteTtl) {
        this.repo = repo;
        this.pendingRepo = pendingRepo;
        this.inviteRepo = inviteRepo;
        this.audit = audit;
        this.totp = totp;
        this.crypto = crypto;
        this.props = props;
        this.inviteTtl = inviteTtl;
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
     * inviteRequired: ต้องแสดงรหัสเชิญที่ admin ออกให้ก่อน จึงจะได้ secret (ผิด = ไม่เห็น secret เลย)
     * คืนผลเป็นค่าแทนการ throw เพราะการนับครั้งที่กรอกรหัสเชิญผิดต้อง commit ไม่ถูก rollback
     */
    @Transactional
    public StartOutcome startEnrollment(String realm, String userId, String issuerLabel, String accountName,
                                        boolean inviteRequired, String inviteCode) {
        String id = MfaCredential.key(realm, userId);
        if (repo.existsById(id)) {
            return new StartOutcome(StartStatus.ALREADY_ENROLLED, null);
        }
        if (inviteRequired && !consumeInvite(id, inviteCode)) {
            return new StartOutcome(StartStatus.INVITE_INVALID, null);
        }
        byte[] secret = totp.newSecret();
        pendingRepo.save(new MfaPending(id, crypto.encrypt(secret, id), Instant.now().plus(props.enrollTtl())));
        return new StartOutcome(StartStatus.OK,
                new EnrollStart(totp.toBase32(secret), totp.otpauthUri(issuerLabel, accountName, secret)));
    }

    /**
     * admin ออกรหัสเชิญ (แทนของเดิมของ user คนนั้น) บันทึก audit ใน transaction เดียวกัน
     * @return empty ถ้า user มี MFA อยู่แล้ว (ต้อง reset ก่อน)
     */
    @Transactional
    public Optional<Invite> createInvite(String realm, String userId, AuditService.Ctx ctx) {
        String id = MfaCredential.key(realm, userId);
        if (repo.existsById(id)) {
            return Optional.empty();
        }
        char[] chars = new char[INVITE_LENGTH];
        for (int i = 0; i < chars.length; i++) {
            chars[i] = INVITE_ALPHABET.charAt(random.nextInt(INVITE_ALPHABET.length()));
        }
        String code = new String(chars);
        Instant expires = Instant.now().plus(inviteTtl);
        inviteRepo.save(new MfaInvite(id, hashInvite(id, code), expires));   // save = แทนที่ของเดิม (id เดียวกัน)
        audit.record("INVITE_ISSUED", realm, userId, ctx, "ttl=" + inviteTtl);
        return Optional.of(new Invite(code.substring(0, 5) + "-" + code.substring(5), expires));
    }

    private boolean consumeInvite(String id, String input) {
        MfaInvite invite = inviteRepo.findByIdForUpdate(id).orElse(null);
        if (invite == null) {
            return false;
        }
        if (invite.getExpiresAt().isBefore(Instant.now())) {
            inviteRepo.delete(invite);
            return false;
        }
        String code = input == null ? "" : input.replaceAll("[\\s-]", "").toUpperCase(Locale.ROOT);
        boolean ok = MessageDigest.isEqual(
                invite.getCodeHash().getBytes(StandardCharsets.UTF_8),
                hashInvite(id, code).getBytes(StandardCharsets.UTF_8));
        if (ok) {
            inviteRepo.delete(invite);      // ใช้ได้ครั้งเดียว
            return true;
        }
        invite.setAttempts(invite.getAttempts() + 1);
        if (invite.getAttempts() >= INVITE_MAX_ATTEMPTS) {
            inviteRepo.delete(invite);      // ถูกเดาเกินจำนวน: ต้องให้ admin ออกใหม่
        } else {
            inviteRepo.save(invite);
        }
        return false;
    }

    private static String hashInvite(String id, String code) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest((id + ":" + code).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(h);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
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

    /** reset MFA (admin กดให้ user ที่ทำเครื่องหาย) เปิดเป็น endpoint เฉพาะ client ที่ admin: true */
    @Transactional
    public void reset(String realm, String userId, AuditService.Ctx ctx) {
        String id = MfaCredential.key(realm, userId);
        boolean existed = repo.existsById(id);
        repo.deleteById(id);
        pendingRepo.deleteById(id);
        inviteRepo.deleteById(id);
        audit.record("MFA_RESET", realm, userId, ctx, existed ? "had-credential" : "no-credential");
    }
}
