package com.ktb.kcmfa.starter;

/** ต้องตรงกับ MfaService.Result ฝั่ง mfa-service */
public enum MfaResult {
    OK, BAD_CODE, LOCKED, NOT_ENROLLED, NO_PENDING, ALREADY_ENROLLED
}
