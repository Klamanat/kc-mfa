# ฝั่งหน้าจอ (Frontend)

หน้าจอคุยกับ backend ของเว็บตัวเอง (endpoint จาก starter) เท่านั้น ไม่เรียก Keycloak หรือ MFA service โดยตรง

## หน้าจอที่ต้องมี 3 หน้า

| หน้า | ใช้เมื่อ | ทำอะไร |
|---|---|---|
| 1. Login | เสมอ | กรอก username/password |
| 2. กรอก OTP | `status = MFA_REQUIRED` | กรอกโค้ด 6 หลักจากแอป |
| 3. ตั้งค่า MFA ครั้งแรก (QR) | `status = ENROLL_REQUIRED` | สแกน QR แล้วกรอกโค้ดยืนยัน |

## State machine

```
Login ──POST /login──> status?
   ├─ OK               -> เข้าระบบ (เว็บที่ไม่บังคับ MFA และ user ยังไม่มี MFA)
   ├─ MFA_REQUIRED     -> หน้า OTP        ──POST /mfa/verify──> tokens -> เข้าระบบ
   └─ ENROLL_REQUIRED  -> หน้า QR  ──POST /mfa/enroll/start──> แสดง QR
                                    ──POST /mfa/enroll/confirm──> tokens -> เข้าระบบ
```

เก็บ `challengeId` ไว้ใน memory/state ของหน้า (ไม่ใส่ localStorage และไม่ใส่ใน URL)
หน้า OTP และหน้า QR ไม่มีทางเข้าถ้าไม่มี `challengeId`

## Login ผ่าน OAuth provider ภายนอก (ถ้า backend เปิด `kcmfa.oauth.enabled`)

```
ปุ่ม "เข้าสู่ระบบด้วย ..." ──เปลี่ยนหน้า (ไม่ใช่ fetch)──> GET /api/auth/oauth/login ──> หน้า login ของ provider
provider ──> backend ──302──> หน้าเว็บ (success-redirect) ──POST /oauth/result──> status? (เหมือนผลของ /login)
                     └─302──> failure-redirect?error=oauth_failed | mfa_unavailable
```

- เริ่มด้วย `window.location.assign("/api/auth/oauth/login")` ห้ามใช้ `fetch` (ต้องเป็น top-level navigation)
- หน้า success-redirect เรียก `POST /oauth/result` **หนึ่งครั้ง** ตอนโหลด (body ว่าง, `credentials: "same-origin"`)
  แล้วเข้า state machine เดิม ผลรับได้ครั้งเดียวภายใน 1 นาที ถ้าได้ `401` (รีเฟรชหน้า/หมดอายุ) ให้กลับหน้า Login
- หน้าเว็บไม่ต้องแตะ `code`, `state` หรือ cookie เอง

```ts
export const oauthLogin = () => window.location.assign("/api/auth/oauth/login");
export const oauthResult = () => api<LoginResult>("/oauth/result", {});
```

## หน้า OTP
- input เดียว 6 หลัก: `inputmode="numeric"`, `autocomplete="one-time-code"`, `maxlength="6"`
- ส่งอัตโนมัติเมื่อกรอกครบ 6 หลัก หรือมีปุ่มยืนยัน
- ข้อความตาม HTTP status (อย่าบอกรายละเอียดเกินจำเป็น):
  - `401` + ยังมี challenge: "รหัสไม่ถูกต้อง ลองอีกครั้ง" (เหลือกี่ครั้งตามที่ backend กำหนด)
  - `401` ตอน challenge หมดอายุ/ถูกทิ้ง: พากลับหน้า Login ให้กรอกรหัสผ่านใหม่
  - `429`: "ลองผิดหลายครั้งเกินไป กรุณารอสักครู่" (บัญชีถูกล็อกชั่วคราว)
  - `503`: "ระบบยืนยันตัวตนไม่พร้อมใช้งาน ลองใหม่ภายหลัง"
- ปุ่ม "กลับไปหน้า Login" และบอกว่าถ้าทำเครื่องหาย ให้ติดต่อผู้ดูแล (ขั้นตอน reset ต้องออกแบบแยก)

## หน้า QR (ลงทะเบียนครั้งแรก)
1. เมื่อเข้าหน้า เรียก `POST /mfa/enroll/start` หนึ่งครั้ง ได้ `{secret, otpauthUri}`
2. สร้าง QR จาก `otpauthUri` ที่ฝั่ง browser (เช่น ไลบรารี `qrcode`) ห้ามส่ง URI นี้ไปให้บริการภายนอกสร้าง QR
3. แสดง `secret` เป็นตัวอักษรให้คัดลอกกรอกเองได้ (สำหรับคนที่สแกนไม่ได้) เป็นกลุ่มละ 4 ตัว
4. ให้ user กรอกโค้ด 6 หลักที่แอปแสดง แล้วเรียก `POST /mfa/enroll/confirm`
5. สำเร็จแล้วได้ tokens เข้าระบบได้เลย
6. อย่า cache หน้านี้ และไม่ log ค่า secret ใน console/analytics/error tracker
7. ถ้ารีเฟรชหน้า: เรียก `enroll/start` ใหม่ได้ (service สร้าง secret ใหม่แทนอันเดิม QR เก่าใช้ไม่ได้แล้ว ควรบอก user)
8. `409`: user มี MFA อยู่แล้ว ให้พากลับหน้า Login

ข้อความแนะนำบนหน้า: ติดตั้งแอป Authenticator (Google/Microsoft Authenticator, Authy ฯลฯ) -> สแกน QR -> กรอกโค้ด

## ตัวอย่างโค้ด (framework-agnostic, TypeScript)

```ts
type LoginResult =
  | { status: "OK"; tokens: Tokens }
  | { status: "MFA_REQUIRED"; challengeId: string }
  | { status: "ENROLL_REQUIRED"; challengeId: string };

async function api<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`/api/auth${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    credentials: "same-origin",
  });
  if (!res.ok) throw Object.assign(new Error(res.statusText), { status: res.status });
  return res.json() as Promise<T>;
}

export const login = (username: string, password: string) =>
  api<LoginResult>("/login", { username, password });

export const verifyOtp = (challengeId: string, code: string) =>
  api<Tokens>("/mfa/verify", { challengeId, code });

export const enrollStart = (challengeId: string) =>
  api<{ secret: string; otpauthUri: string }>("/mfa/enroll/start", { challengeId });

export const enrollConfirm = (challengeId: string, code: string) =>
  api<Tokens>("/mfa/enroll/confirm", { challengeId, code });
```

```ts
// หน้า QR: ใช้ไลบรารี qrcode (npm i qrcode) วาดลง <canvas>
import QRCode from "qrcode";

async function showEnrollment(challengeId: string, canvas: HTMLCanvasElement) {
  const { secret, otpauthUri } = await enrollStart(challengeId);
  await QRCode.toCanvas(canvas, otpauthUri, { width: 220, margin: 1 });
  return secret.match(/.{1,4}/g)!.join(" "); // แสดงใต้ QR ให้คัดลอกได้
}
```

## ข้อควรระวัง
- ปุ่มส่งต้องกันกดซ้ำระหว่างรอผล (ไม่งั้นนับเป็นการลองผิดหลายครั้ง)
- เวลาในเครื่อง user ไม่ต้องตรงกับ server เพราะแอป Authenticator คำนวณเอง แต่ถ้าโค้ดถูกปฏิเสธบ่อย
  ให้แนะนำเช็กเวลาเครื่องมือถือให้เป็นอัตโนมัติ
- ใช้ HTTPS เท่านั้น และตั้ง `Cache-Control: no-store` ให้ response ของ endpoint เหล่านี้
- ถ้าจะให้ tokens ไม่ผ่าน JavaScript เลย ให้ backend เซ็ต httpOnly cookie แล้วตอบแค่ `{status:"OK"}`
