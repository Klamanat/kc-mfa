# demo-backend

เว็บตัวอย่างที่ใช้ `mfa-spring-boot-starter`: login ผ่าน Keycloak (password grant) + MFA ด้วย Google Authenticator
แล้วเรียก API ที่ป้องกันด้วย access token (`/api/me`, `/api/orders`)

## Flow

```
หน้าเว็บ ──POST /api/auth/login──► AuthController ──► starter ──password grant──► Keycloak
                                                          └─ status ─► mfa-service
        ◄── status: MFA_REQUIRED | ENROLL_INVITE_REQUIRED | ENROLL_REQUIRED | OK   (challengeId อยู่ใน cookie httpOnly)
        ──POST /api/auth/mfa/verify  หรือ  /mfa/enroll/start (+inviteCode) → /mfa/enroll/confirm──► cookie access token
        ──GET /api/me, /api/orders (cookie หรือ Authorization: Bearer)──► Spring Security ตรวจ JWT + azp
```

## รันทั้งชุดด้วย Docker (ไม่ต้องมี Keycloak เอง)

```powershell
copy .env.example .env      # ใส่ทุกช่อง (ไม่มีค่าลับเขียนไว้ในไฟล์ของ repo; วิธีสร้างค่าสุ่มอยู่ในไฟล์ .env.example)
docker compose up --build
```

เปิด `http://localhost:8080` แล้ว login ด้วย `demo` + ค่า `DEMO_USER_PASSWORD` (Keycloak admin อยู่ที่ `http://localhost:8180`)
ชุดนี้ import realm `brand-a` จาก `demo/keycloak/` (client `web1-backend` สำหรับเว็บ และ `mfa-admin` สำหรับผู้ดูแล
พร้อม Audience mapper และ claim `client_id`) โดยค่าลับมาจาก `.env`: compose แทนค่า `__NAME__` ในไฟล์ realm ก่อน Keycloak เริ่ม
(ค่าลับต้องเป็น A-Z a-z 0-9 + / = _ - . เท่านั้น ซึ่งค่าที่สร้างด้วยคำสั่งใน `.env.example` เป็นแบบนั้น)

**Keycloak import realm แค่ครั้งแรกที่ container ถูกสร้าง** ถ้าเปลี่ยนค่าใน `.env` ภายหลังต้อง `docker compose down` แล้ว `up --build` ใหม่
(ข้อมูล Keycloak ของ dev อยู่ใน container จึงถูกสร้างใหม่ ส่วน MFA ใน Postgres ยังอยู่ ใช้ `down -v` เฉพาะเมื่อต้องการล้าง Postgres ด้วย)

ทุก container ต้องเรียก Keycloak ด้วย host `keycloak:8080` เหมือนกัน เพราะ `iss` ใน token มาจาก host ที่ใช้เรียก

### ผู้ใช้ใหม่ลงทะเบียน MFA ครั้งแรกต้องมีรหัสเชิญ

ชุดนี้ตั้ง `invite-required: true` (`demo/mfa-service.yml`): คนที่รู้แค่รหัสผ่านจะ enroll Authenticator ไม่ได้ ผู้ดูแลต้องออกรหัสเชิญให้ก่อน

```powershell
$env:MFA_ADMIN_SECRET = "<ค่าเดียวกับใน .env>"
.\demo\mfa-admin.ps1 -UserId <sub ของ user>          # ออกรหัสเชิญ (ใช้ได้ครั้งเดียว อายุ 30 นาที)
.\demo\mfa-admin.ps1 -UserId <sub ของ user> -Reset   # ล้าง MFA เดิม (เช่นเปลี่ยนเครื่อง) แล้วออกรหัสเชิญใหม่
```

`sub` ดูที่ Keycloak admin > Users > เลือก user > ช่อง ID แล้วส่งรหัสให้ user ผ่านช่องทางอื่นที่ไม่ใช่หน้า login
ถ้าจะล้างทุกอย่างรวมข้อมูลใน Postgres: `docker compose down -v`

ส่วนด้านล่างคือการรันแบบไม่ใช้ Docker

## สิ่งที่ต้องมีก่อนรัน

1. Keycloak ที่มี realm (ค่าเริ่มต้น `brand-a`) และ client `web1-backend`: confidential,
   เปิด **Direct Access Grants** และ **Service Accounts**, เพิ่ม **Audience mapper** ให้ token มี `aud: mfa-service`
2. `mfa-service` รันอยู่ (ดู README ราก) และ `mfa.clients` มี `(brand-a, web1-backend)`
   ส่วน `trusted-issuers` ต้องตรงกับ `iss` ของ Keycloak เป๊ะ
3. user ทดสอบใน realm นั้น

## รัน

```powershell
$env:KC_CLIENT_SECRET = "<secret ของ web1-backend>"
$env:DEMO_COOKIE_SECURE = "false"      # เฉพาะตอนลองบน http://localhost (ค่าเริ่มต้น true = cookie ส่งผ่าน HTTPS เท่านั้น)
# ถ้าไม่ใช่ค่าเริ่มต้น: KC_BASE_URL, KC_REALM, KC_CLIENT_ID, KC_ISSUER_URI, MFA_SERVICE_URL
mvn -pl demo-backend -am spring-boot:run
```

เปิด `http://localhost:8080` → login → (ครั้งแรก) ใส่รหัสเชิญถ้าเว็บเปิด invite-required แล้วสแกน QR ด้วย Google Authenticator → ยืนยันรหัส → ดูข้อมูลจาก API

## ความปลอดภัยของ demo (สิ่งที่ทำแล้ว)

- `AuthController` ของ demo แทนของ starter (`kcmfa.controller.enabled=false`): access token และ `challengeId` ส่งเป็น cookie httpOnly + SameSite=Strict
  (ไม่อยู่ใน JSON, JS อ่านไม่ได้) และไม่ส่ง refresh_token ให้ browser เลย; เรียก API ด้วย `Authorization: Bearer` แทน cookie ก็ได้
- cookie เป็น `Secure` โดยปริยาย (ตั้ง `DEMO_COOKIE_SECURE=false` เองเฉพาะตอนลองบน http)
- API รับเฉพาะ token ที่ออกให้ client ของเว็บนี้ (`azp`) และไม่ใช่ token ของ service account (`LoginTokenValidator`)
- rate limit 10 ครั้ง/นาที: ต่อ IP และต่อชื่อผู้ใช้ที่ login, ต่อ IP ที่ใส่ OTP / รหัสเชิญ / ขอ QR (in-memory instance เดียว)
- header: CSP (`default-src 'none'`, สคริปต์/สไตล์จาก origin เดียวกัน ไม่มี inline), `Referrer-Policy: no-referrer`, `Permissions-Policy`, `X-Frame-Options`/`nosniff` ของ Spring Security
- QR วาดฝั่ง server ด้วย zxing (`POST /api/auth/qr` รับเฉพาะ `otpauth://totp/`) ไม่ดึง library จากภายนอก และไม่เก็บ secret ไว้ที่ใด

## ข้อจำกัดที่ยังมี

- rate limit เป็น in-memory: หลัง reverse proxy ต้องตั้ง `server.forward-headers-strategy` ไม่งั้นทุกคนมี IP เดียวกัน (การนับต่อชื่อผู้ใช้ยังทำงาน)
  แต่ถ้าเปิด header นี้โดยไม่มี proxy จริง ผู้โจมตีปลอม `X-Forwarded-For` เลี่ยงการนับต่อ IP ได้ หลาย instance ควรย้ายไป gateway/Redis
- การนับต่อชื่อผู้ใช้ทำให้คนอื่นยิง login ใส่ชื่อของเหยื่อจนเหยื่อ login ไม่ได้ชั่วคราว (1 นาที) เป็นข้อแลกเปลี่ยนกับการกัน brute-force
- CSRF ปิดไว้ เพราะ cookie เป็น SameSite=Strict และ endpoint ที่ใช้ cookie เป็น GET ที่ไม่แก้ข้อมูล ถ้าเพิ่ม POST/PUT/DELETE ต้องเปิด CSRF
- logout ได้แค่ล้าง cookie (demo ไม่เก็บ refresh_token จึงยกเลิก session ที่ Keycloak ไม่ได้ access token ที่ออกไปแล้วใช้ได้จนหมดอายุ)
- Keycloak ในชุด docker เป็น `start-dev` บน HTTP ใช้ในเครื่องเท่านั้น
- Redis/หลาย instance: ตั้ง `kcmfa.store=redis` และ `kcmfa.redis-encryption-key` ตามหัวข้อใน README ราก
- ยังไม่ได้ compile/รันของ module นี้และ mfa-service (สภาพแวดล้อมของผมดาวน์โหลด dependency ไม่ได้)
