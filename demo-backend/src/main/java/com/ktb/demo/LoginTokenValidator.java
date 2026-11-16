package com.ktb.demo;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * รับเฉพาะ access token ของ user ที่ login ผ่าน client ของเว็บนี้:
 *   - azp ต้องเป็น client-id ของเว็บนี้ (token ของ client อื่นใน realm เดียวกันใช้ไม่ได้)
 *   - ต้องไม่ใช่ token ของ service account (client_credentials) ซึ่ง azp = client เดียวกันแต่ไม่ใช่ user
 *     วิธีแยกเดียวกับที่ MFA service ใช้: service account token มี claim client_id/clientId เท่ากับ azp
 */
final class LoginTokenValidator implements OAuth2TokenValidator<Jwt> {

    private static final OAuth2Error WRONG_CLIENT =
            new OAuth2Error("invalid_token", "Token was not issued to this web client", null);
    private static final OAuth2Error SERVICE_ACCOUNT =
            new OAuth2Error("invalid_token", "Service account tokens are not accepted", null);

    private final String clientId;

    LoginTokenValidator(String clientId) {
        this.clientId = clientId;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        String azp = jwt.getClaimAsString("azp");
        if (!clientId.equals(azp)) {
            return OAuth2TokenValidatorResult.failure(WRONG_CLIENT);
        }
        if (azp.equals(jwt.getClaimAsString("client_id")) || azp.equals(jwt.getClaimAsString("clientId"))) {
            return OAuth2TokenValidatorResult.failure(SERVICE_ACCOUNT);
        }
        return OAuth2TokenValidatorResult.success();
    }
}
