# kc-mfa: TOTP MFA กลาง สำหรับหลายเว็บที่ login ผ่าน Keycloak (Spring Boot 3 / Java 17)

```
 Browser ──> Web backend (ใช้ mfa-spring-boot-starter) ──password grant──> Keycloak (realm ของเว็บนั้น)
                    │
                    └── Bearer token (client_credentials ของ backend เอง) ──> mfa-service (กลาง)
                                                                              เก็บ secret, ตรวจ OTP, lockout, policy
```

- **mfa-service**: เก็บ TOTP secret (AES-256-GCM), ตรวจโค้ด, กัน replay, lockout, policy ต่อเว็บ
  ใช้ key `(realm, userId)` โดย realm มาจาก `iss` และเว็บที่เรียกมาจาก `azp` ใน token ของผู้เรียก
  backend ของ realm A จึงยุ่งกับ user ของ realm B ไม่ได้
- **mfa-spring-boot-starter**: ใส่ใน backend ของแต่ละเว็บ ได้ endpoint login / verify / enroll พร้อมใช้
  จัดการ challenge, ถือ token ไว้จนกว่าผ่าน OTP, fail-closed ถ้า MFA service ล่ม, revoke session ที่ Keycloak เมื่อไม่ผ่าน
- ฝั่งหน้าจอ: ดู `docs/frontend.md`

## Flow ของเว็บ

```
POST /api/auth/login            {username,password}
  -> {status:"OK", tokens}                    ยังไม่มี MFA และเว็บนี้ไม่บังคับ
  -> {status:"MFA_REQUIRED", challengeId}     user มี MFA แล้ว
  -> {status:"ENROLL_REQUIRED", challengeId}  เว็บนี้บังคับ และ user ยังไม่มี MFA
  -> {status:"ENROLL_INVITE_REQUIRED", challengeId}  เหมือนข้างบน แต่ service ตั้ง invite-required: ต้องใส่รหัสเชิญจาก admin
  -> 401 / 503

POST /api/auth/mfa/verify          {challengeId, code}   -> tokens
POST /api/auth/mfa/enroll/start    {challengeId, inviteCode?}  -> {secret, otpauthUri}   (รหัสเชิญผิด = 403)
POST /api/auth/mfa/enroll/confirm  {challengeId, code}   -> tokens
```

### Login ผ่าน OAuth provider ภายนอก (ไม่ใช่ Keycloak) — ตัวเลือก `kcmfa.oauth.enabled=true`

```
GET  /api/auth/oauth/login      -> 302 ไปหน้า login ของ provider (Authorization Code + PKCE S256, state, nonce)
GET  /api/auth/oauth/callback   <- provider redirect กลับ: backend แลก code เป็น token, ระบุตัว user, ถาม MFA service
                                -> 302 ไป success-redirect (หรือ failure-redirect?error=oauth_failed|mfa_unavailable)
POST /api/auth/oauth/result     -> ผลแบบเดียวกับ /login: {status:"OK",tokens} | MFA_REQUIRED | ENROLL_REQUIRED
                                   จากนั้นใช้ /mfa/verify, /mfa/enroll/* เดิม
```

- provider ทำหน้าที่แค่ "ปัจจัยแรก" แทนรหัสผ่าน OTP ยังตรวจที่ mfa-service กลาง
  backend ยังต้องมี service account ที่ Keycloak (`kcmfa.keycloak.*`) ไว้เรียก mfa-service เหมือนเดิม
- `tokens` ที่หน้าเว็บได้คือ token response ของ provider นั้น (ไม่ใช่ของ Keycloak)
- user ถูกระบุด้วย `"{provider}.{base64url(SHA-256(sub))}"` ภายใต้ realm ของ backend
  **MFA ของบัญชี Keycloak กับบัญชี provider ภายนอกจึงเป็นคนละชุด** ถ้าต้องการให้เป็นคนเดียวกันต้องทำ account linking ในเว็บเอง
  และห้ามเปลี่ยนค่า `provider` / `user-id-claim` หลังมีคน enroll แล้ว (MFA เดิมจะหาไม่เจอ)
- ผล login และ `challengeId` ไม่ผ่าน URL: เก็บฝั่ง server แล้วหน้าเว็บมารับครั้งเดียวด้วย cookie `__Host-kcmfa_oauth` (httpOnly, Secure, SameSite=Lax)
  cookie เดียวกันผูก `state` กับ browser ที่เริ่ม login (กัน login CSRF) prefix `__Host-` กัน subdomain อื่นฝัง cookie นี้ให้เหยื่อ
  (ถ้าตั้ง `cookie-secure: false` หรือ `cookie-path` ไม่ใช่ `/` เช่น dev บน http จะใช้ชื่อ `kcmfa_oauth` แทน)
- ไม่ผ่าน MFA / หมดอายุ / MFA service ล่ม: revoke ที่ `revocation-uri` ของ provider (ถ้าตั้ง) ไม่ส่ง token ของ provider ไป Keycloak
- รันหลาย instance: ตั้ง `kcmfa.store=redis` (ดูหัวข้อ Redis ด้านล่าง)

```yaml
kcmfa:
  oauth:
    enabled: true
    provider: google                      # [a-z0-9-]{1,16}
    authorization-uri: https://idp.example.com/oauth2/authorize
    token-uri: https://idp.example.com/oauth2/token
    user-info-uri: https://idp.example.com/userinfo   # จำเป็นถ้า provider ไม่ออก id_token
    revocation-uri: https://idp.example.com/oauth2/revoke   # ตัวเลือก (RFC 7009)
    client-id: web1
    client-secret: ${OAUTH_CLIENT_SECRET}
    redirect-uri: https://web1.example.com/api/auth/oauth/callback   # ต้องตรงกับที่ลงทะเบียนกับ provider เป๊ะ
    # ตัวเลือก: scope (openid), client-auth (post | basic), user-id-claim (sub), username-claim (email),
    #          success-redirect (/), failure-redirect (/login), state-ttl (5m), result-ttl (1m),
    #          cookie-secure (true), cookie-path (/)
```

## ตั้งค่า

### Keycloak (ทุก realm / ทุก client ของเว็บ)
1. client เป็น **confidential**
2. เปิด **Direct Access Grants** (ใช้ login) และ **Service Accounts Enabled** (ใช้ขอ token เรียก MFA service)
3. ใน Direct Grant flow **อย่าบังคับ OTP / CONFIGURE_TOTP** (OTP ตรวจที่ MFA service ถ้าตั้งซ้ำ login จะ error)
4. ปิดทางเรียก token endpoint จากภายนอก ให้เข้าถึงได้เฉพาะ backend ไม่งั้นข้าม MFA ได้
5. Keycloak 16 URL มี `/auth` นำหน้า `/realms/...`

### mfa-service (`application.yml`)
- DB เป็น **PostgreSQL** (ใช้ cluster ที่มีอยู่แล้ว แยก schema/user): ตั้ง `MFA_DB_URL`, `MFA_DB_USER`, `MFA_DB_PASSWORD`
  และ `MFA_DB_POOL_SIZE` (เริ่มต้น 20 ต่อ instance) schema สร้างด้วย Flyway จาก `db/migration/V1__init.sql`
  ตอน start (user ของ DB ต้องมีสิทธิ์สร้างตารางใน schema นั้น หรือให้ DBA รัน script เองแล้วตั้ง `spring.flyway.enabled=false`)
- service ไม่เก็บ state ในตัว รันได้หลาย instance หลัง load balancer
- `mfa.encryption-key` (`openssl rand -base64 32` เก็บใน secret manager/KMS)
- `mfa.trusted-issuers`: iss ของแต่ละ realm ให้ตรงกับใน token เป๊ะ
  (ตรวจได้ด้วยการ decode access token ของ service account)
  ชื่อ realm ต้องไม่ซ้ำกันระหว่าง issuer (เช่น Keycloak UAT กับ PROD ที่มี realm ชื่อเดียวกัน) ไม่งั้น service ไม่ยอม start
  ให้แยก mfa-service ต่อ Keycloak
- `mfa.required-audience` (ค่าเริ่มต้น `mfa-service`): token ต้องมี `aud` นี้
  ใน Keycloak เพิ่ม mapper ชนิด **Audience** ให้ client ของแต่ละเว็บ ใส่ค่า `mfa-service` เป็น custom audience ลงใน access token
  ถ้ายังไม่ได้เพิ่ม mapper ทุก request จะได้ 403
- `mfa.clients`: allowlist ของ (realm, client-id) พร้อม `enforce` และ `issuer-label`
- **รหัสเชิญ (`invite-required` ต่อ client: ไม่ตั้ง = ตาม `enforce` จึงเปิดโดยปริยายในเว็บที่บังคับ MFA, ตั้ง `false` เองเท่านั้นจึงจะปิด)**: กันคนที่รู้แค่รหัสผ่านของ user ที่ยังไม่เคยลงทะเบียน
  มาลงทะเบียน Authenticator ของตัวเองก่อนเจ้าของ ลงทะเบียนครั้งแรกจึงต้องมีรหัสที่ admin ออกให้ผ่านช่องทางอื่นที่ไม่ใช่หน้า login
  - admin = client ที่ประกาศ `admin: true` (service account ของเครื่องมือผู้ดูแล แยกจาก backend ของเว็บ ต้องมี Audience mapper `mfa-service` เหมือนกัน)
  - `POST /v1/users/{userId}/mfa/invite` -> `{code, expiresAt}` รหัส 10 ตัวอักษร ใช้ได้ครั้งเดียว อายุ `mfa.invite-ttl` (ค่าเริ่มต้น 30m)
    เก็บเฉพาะ hash กรอกผิดครบ 5 ครั้งรหัสถูกยกเลิก (ต้องออกใหม่) ตอบ 409 ถ้า user มี MFA แล้ว
  - `DELETE /v1/users/{userId}/mfa` reset MFA ของ user (เช่นทำเครื่องหาย) แล้วออกรหัสเชิญใหม่ได้
  - ข้อแลกเปลี่ยน: ผู้ที่รู้รหัสผ่านและเดารหัสเชิญผิดซ้ำจะ "เผา" รหัสเชิญของ user ได้ (ไม่ได้ MFA ไป แต่ user ต้องขอใหม่)
  - ตัวอย่างเครื่องมือ: `demo/mfa-admin.ps1`
  - **ด่านของ endpoint admin (`AdminGuard`)**: นอกจาก token ของ client ที่ `admin: true` ต้องผ่านครบทุกข้อ
    1. เรียกจาก IP ที่อยู่ใน `mfa.admin.allowed-cidrs` (เว้นว่าง = ปิดทั้งหมด; หลัง proxy ต้องตั้ง `server.forward-headers-strategy` และให้ proxy เป็นทางเดียวที่เข้าถึง service)
    2. ส่ง header `X-Admin-Actor` (ชื่อผู้ดูแล 1-64 ตัวอักษร) เพื่อลงใน audit log **ค่านี้ผู้เรียกระบุเอง ไม่ได้พิสูจน์ตัวตน**
       client secret ตัวเดียวแยกคนไม่ได้ ถ้าต้องการพิสูจน์รายคนต้องให้ผู้ดูแลแต่ละคนมี service account (client `admin: true`) ของตัวเอง
    3. ไม่เกิน `mfa.admin.max-per-hour` (20) ครั้ง/client/ชนิดเหตุการณ์/ชั่วโมง (ออกรหัสเชิญ กับ reset นับแยกกัน)
  - **audit log**: ตาราง `mfa_audit` (เพิ่มอย่างเดียว ให้สิทธิ์ INSERT/SELECT เท่านั้น แล้วส่งออกไปเก็บที่อื่นด้วย) และ logger `mfa.audit`
    เหตุการณ์: `INVITE_ISSUED`, `MFA_RESET`, `INVITE_REJECTED`, `ENROLL_STARTED`, `ENROLL_CONFIRMED` (การปฏิเสธของ admin เขียนลง log เป็น `admin-denied` ไม่ลงตาราง)
    ยังไม่มีการแจ้งเตือนอัตโนมัติ ต้องตั้ง alert เองจาก log/ตาราง (เช่น `INVITE_REJECTED` ถี่ผิดปกติ, `admin-denied`)
  - **ยังไม่มี**: การอนุมัติสองชั้น (คนหนึ่งขอ อีกคนอนุมัติ) และการพิสูจน์ตัวตนรายคนของผู้ดูแล
- **หลักฐานของ user (`X-User-Token`)**: starter แนบ token ของ user ไปกับทุก request เอง service ตรวจลายเซ็นและดูว่าเป็นของ `userId` ที่ขอ
  - user ของ Keycloak: access token ต้องมี `azp` = client-id ของ backend ถ้า token ของ user ออกโดย client อื่นของ realm เดียวกัน
    (เช่นเว็บที่ใช้ wrapper เดิมกับ client อีกตัว) ให้ใส่ไว้ใน `login-client-ids` ของ client นั้น
  - user จาก OAuth ภายนอก: ต้องประกาศ provider ใน `external-providers` ของ client (`provider` ตรงกับ `kcmfa.oauth.provider`,
    `issuer` = iss ของ id_token, `audience` = client-id ที่ลงทะเบียนกับ provider) service ตรวจ id_token กับ JWKS ของ issuer นั้น
    จึงต้องออกเน็ตไปถึง issuer ได้ และเว็บต้องใช้ `user-id-claim: sub` (ค่าเริ่มต้น)
  - provider ที่ไม่ออก id_token (OAuth2 ล้วน): ประกาศโดยเว้น `issuer` ว่าง = ยอมรับโดยไม่มีหลักฐาน (ความเสี่ยงเดิมยังอยู่เฉพาะ user ของ provider นั้น)
  - `mfa.user-token-grace` (15m): token หมดอายุแล้วยังรับได้อีกเท่านี้ ควรไม่น้อยกว่า `kcmfa.challenge-ttl`
- รับเฉพาะ token ของ **service account** (client_credentials): ต้องมี claim `client_id` หรือ `clientId` เท่ากับ `azp`
  Keycloak ใส่ให้เองผ่าน mapper "Client ID" ตอนเปิด Service Accounts ถ้าลบ mapper นี้ออก service จะตอบ 403
  ตรวจได้ด้วยการ decode access token ของ service account ว่ามี claim นี้จริงในรุ่น Keycloak ที่ใช้

### แต่ละเว็บ (Spring Boot)
```xml
<dependency>
  <groupId>com.ktb.kcmfa</groupId>
  <artifactId>mfa-spring-boot-starter</artifactId>
  <version>0.2.1</version>
</dependency>
```
```yaml
kcmfa:
  keycloak:
    base-url: https://keycloak.example.com/auth
    realm: brand-a
    client-id: web1-backend
    client-secret: ${KC_CLIENT_SECRET}
  mfa-service:
    url: https://mfa.internal.example.com
  store: redis        # เว็บที่รันหลาย instance (ค่าเริ่มต้น memory = instance เดียว) ดูหัวข้อ Redis ด้านล่าง
  # ตัวเลือก: base-path (default /api/auth), challenge-ttl (5m), max-attempts (5),
  #          connect-timeout (2s), read-timeout (5s)  <- ใช้กับทั้ง Keycloak และ MFA service
  #          sweep-interval (30s)                      <- รอบเก็บกวาด challenge ที่หมดอายุ
  #          controller.enabled=false ถ้าจะเขียน controller เองแล้วฉีด LoginFlow ไปใช้
```

### เว็บที่รันหลาย instance: `kcmfa.store=redis`
เพิ่ม `spring-boot-starter-data-redis` ในเว็บ ตั้ง `spring.data.redis.*` ตามปกติ แล้วตั้ง `kcmfa.store: redis`
challenge และสถานะ OAuth จะเก็บใน Redis ทุก instance เห็นร่วมกัน ไม่ต้องใช้ sticky session
- ต้องใช้ Redis 6.2+ (คำสั่ง `GETDEL`) เมื่อเปิด `kcmfa.oauth`
- key ขึ้นต้นด้วย `kcmfa:{client-id}:` เปลี่ยนได้ด้วย `kcmfa.redis-key-prefix` **ห้ามซ้ำกันระหว่างเว็บที่ใช้ Redis ร่วมกัน**
- token ของ user อยู่ใน Redis ระหว่างรอ OTP (ไม่เกิน `challenge-ttl` + 10 นาที) จึง**ถูกเข้ารหัส AES-256-GCM เสมอ** ด้วย `kcmfa.redis-encryption-key`
  (base64 32 bytes: `openssl rand -base64 32`; ผูกกับ key ของ Redis ย้ายค่าไปสวม key อื่นไม่ได้) ไม่ตั้งคีย์ = เว็บ start ไม่ขึ้น
  ยกเว้นตั้ง `kcmfa.redis-allow-plaintext: true` เอง ยังไม่รองรับหมุนคีย์ (เปลี่ยนคีย์แล้ว challenge ที่ค้างอยู่ต้อง login ใหม่) และ Redis ควรเปิด auth + TLS อยู่ดี
- challenge ที่หมดอายุยังถูก revoke session เหมือนแบบ in-memory (instance เดียวเท่านั้นที่ได้ทำ ไม่ซ้ำกัน)
- การนับครั้งที่กรอกผิดเป็น atomic (`INCR`) ยิงพร้อมกันหลาย instance ก็ไม่เกิน `max-attempts`
- ตั้ง `store: redis` แต่ไม่มี dependency ของ Redis: เว็บจะ start ไม่ขึ้น (ไม่ตกไปใช้ in-memory เงียบๆ)

### ใช้กับ wrapper เดิมที่เรียก Keycloak อยู่แล้ว (ไม่ใช้ controller ของ starter)
ตั้ง `kcmfa.controller.enabled=false` แล้วในโค้ด login เดิม เปลี่ยนจุดที่ "รหัสผ่านผ่านแล้ว"
จากการคืน token ตรงๆ เป็นเรียก `LoginFlow.afterPassword(...)`

```java
// เดิม
Map<String, Object> tokens = existingKeycloakWrapper.login(username, password); // ตรวจรหัสผ่านแล้ว
return tokens;

// ใหม่ (inject LoginFlow)
Map<String, Object> tokens = existingKeycloakWrapper.login(username, password);
LoginFlow.LoginResult r = loginFlow.afterPassword(username, tokens);
//   r.status() = "OK"              -> r.tokens() ใช้สร้าง session ตามเดิม
//   r.status() = "MFA_REQUIRED"    -> คืน r.challengeId() ให้หน้าเว็บ
//   r.status() = "ENROLL_REQUIRED" -> คืน r.challengeId() ให้หน้าเว็บ
```
- `tokens` ต้องเป็น Map ที่มี `access_token` (และควรมี `refresh_token` ไว้ revoke) ถ้า wrapper คืน DTO ให้แปลงเป็น Map ก่อน
  หรือใช้ `afterPassword(username, userId, tokens)` ถ้ารู้ `sub` อยู่แล้ว
- ส่วนที่ต้องทำเองในเว็บ: endpoint `/mfa/verify`, `/mfa/enroll/start`, `/mfa/enroll/confirm`
  (เรียก `loginFlow.verify / enrollStart / enrollConfirm`) และสร้าง session จาก tokens ที่คืนมา

## หลักความปลอดภัยที่ใส่ไว้
- ผู้เรียก MFA service ถูกระบุจาก JWT (iss + azp) และต้องอยู่ใน allowlist ไม่เชื่อค่าที่ส่งมาใน path/body
- access token ของ user (iss/azp เดียวกับ backend) เรียก MFA service ไม่ได้ ต้องเป็น token ของ service account
- backend ต้องแนบ token ของ user คนนั้นทุกครั้ง: backend หรือ client secret ที่ถูกเจาะจึงสั่งล็อก/ลงทะเบียน MFA ได้เฉพาะ user
  ที่เพิ่ง login ผ่านเว็บนั้นจริง ไม่ใช่ user คนไหนก็ได้ใน realm
- ตรวจ OTP / ยืนยัน enroll ของ user เดียวกันทีละ request (`SELECT ... FOR UPDATE`) ยิงพร้อมกันเพื่อเลี่ยง lockout หรือใช้โค้ดซ้ำไม่ได้
- token ต้องออกมาเพื่อ service นี้ (`aud`) token ที่เว็บส่งให้ API อื่นนำมาใช้ต่อที่นี่ไม่ได้
- secret ที่เข้ารหัสผูกกับเจ้าของ (`realm|userId` เป็น AAD ของ AES-GCM) คัดลอกข้ามแถวใน DB แล้วถอดไม่ออก
- enroll ทับ MFA เดิมไม่ได้ (409) ป้องกันคนที่รู้แค่รหัสผ่านมาเปลี่ยน MFA
- secret ที่ยังไม่ยืนยันเก็บใน DB (เข้ารหัส) มี TTL และจำกัดจำนวนครั้งที่ลองยืนยัน
- ผ่าน OTP ครั้งเดียว/โค้ดเดียว (กัน replay), lockout ต่อ user, จำกัดครั้งต่อ challenge
- MFA service ล่ม = login ไม่ผ่าน (fail-closed) และ revoke session ที่ Keycloak ที่เพิ่งเปิด

- ลงทะเบียน MFA ครั้งแรกต้องมีรหัสเชิญจาก admin ไม่ใช่แค่รหัสผ่าน (เปิดโดยปริยายเมื่อ `enforce: true`); admin แยกเป็น client ของตัวเอง
  จำกัด IP, ต้องระบุผู้ดูแล, จำกัดจำนวนครั้งต่อชั่วโมง และมี audit log
- token ที่เก็บใน Redis เข้ารหัส AES-GCM และ start ไม่ขึ้นถ้าไม่ตั้งคีย์

## ข้อจำกัดที่ยอมรับ / ต้องแก้ที่ชั้นอื่น
- **lockout เป็นช่องทางทำให้ user ใช้งานไม่ได้**: ผู้ที่รู้รหัสผ่านกรอก OTP ผิดจนบัญชีถูกล็อกได้ (`lock-after-failures`, `lock-duration`)
  เป็นข้อแลกเปลี่ยนกับการกัน brute-force รหัส 6 หลัก ผู้โจมตีต้องผ่านรหัสผ่านก่อน จึงไม่ใช่ช่องโหว่ที่เข้าถึงบัญชีได้
- **rate limit ที่แท้จริงต้องอยู่ที่ gateway / Keycloak**: limiter ใน demo เป็น in-memory ของ instance เดียว (นับทั้งต่อ IP และต่อชื่อผู้ใช้)
  หลาย instance หรือหลัง proxy ที่ไม่ได้ตั้ง `forward-headers-strategy` ใช้ไม่ได้ผล ให้เปิด brute-force detection ของ Keycloak และ rate limit ที่ gateway
- **Keycloak ในชุด docker เป็น `start-dev` (HTTP)**: production ต้องมี TLS และ hostname ที่ตั้งค่าแล้ว

## ยังต้องทำก่อน production
- ทดสอบ Redis store กับ Redis จริง (เทสต์ตอนนี้ใช้ Redis จำลอง) และทดสอบ migration กับ PostgreSQL จริง
- ทดสอบโหลด (ไม่ได้วัดไว้) และปรับ `MFA_DB_POOL_SIZE` จากผลที่ได้
- ส่ง token เป็น httpOnly+Secure cookie, CSRF, rate limit ต่อ IP ที่ gateway (demo-backend ทำ cookie + rate limit ในเครื่องให้ดูเป็นตัวอย่าง)
- Recovery codes, การอนุมัติสองชั้นของ admin, การแจ้งเตือนจาก audit log, และ export audit ไปที่เก็บที่แก้ไม่ได้
- การเปิด/เปลี่ยน MFA หลัง login แล้ว (ตอนนี้ enroll ทำได้เฉพาะตอน login เมื่อเว็บตั้ง `enforce: true`)
- เพิ่ม audit log (realm, azp, userId, ผล) ใน mfa-service

## สถานะของโค้ด
**ยังไม่เคย compile หรือรันเทสต์ในสภาพแวดล้อมที่เขียน** (ดาวน์โหลด dependency ไม่ได้)
ตรวจ syntax ด้วย javac แล้ว (ไม่พบ syntax error) แต่ยังไม่ผ่านการ type-check กับ library จริง
รัน `mvn test` ที่ root ก่อนใช้งาน เทสต์มี: AES-GCM, TOTP (รวม RFC 6238 vector), otpauth URI, Caller (iss/azp), LoginFlow (fail-closed, challenge, lockout),
OAuthLoginFlow (state/cookie binding, PKCE, nonce/aud, userinfo, fail-closed, sweep), UserTokenVerifier (เจ้าของ token, azp, provider ภายนอก)
เทสต์ของ starter (36 เคส รวม Redis store กับ Redis จำลอง, เข้ารหัสค่าใน Redis, รหัสเชิญ) เคยรันผ่านแบบ offline กับ Spring 6.0.9 / Boot 3.1.0 โดยใช้ stub แทนคลาสที่ใช้ `RestClient`
(`KeycloakClient`, `ExternalOAuthClient`, `MfaServiceClient`, `Http`) สี่คลาสนี้และ mfa-service ทั้ง module ยังไม่เคย compile กับ library จริง
จุดที่ควรดูก่อนถ้า compile ไม่ผ่าน: constructor/method ของ `java-otp` 0.4.0 และ `Jwt.Builder.issuer(...)` ในเทสต์
