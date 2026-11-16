// access token อยู่ใน cookie httpOnly ที่ backend ตั้งให้ JS อ่านไม่ได้ (เบราว์เซอร์แนบไปเองทุก request)
'use strict';

// challengeId อยู่ใน cookie httpOnly (demo_chal) ที่ backend ตั้งให้ ฝั่งนี้ไม่เคยเห็นค่า

const $ = (id) => document.getElementById(id);
const VIEWS = ['s-login', 's-verify', 's-invite', 's-enroll'];
const STEP_OF = { 's-login': 1, 's-verify': 2, 's-invite': 2, 's-enroll': 2 };
const OTP_LENGTH = 6;

/* ---------- ข้อความ error ---------- */
const MESSAGES = {
  login: { 401: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง', 429: 'พยายามบ่อยเกินไป กรุณารอสักครู่แล้วลองใหม่', 503: 'ระบบยืนยันตัวตนไม่พร้อมใช้งานชั่วคราว' },
  invite: { 403: 'รหัสเชิญไม่ถูกต้อง หมดอายุ หรือถูกใช้ไปแล้ว', 429: 'ลองบ่อยเกินไป กรุณารอสักครู่แล้วลองใหม่', 503: 'ระบบยืนยันตัวตนไม่พร้อมใช้งานชั่วคราว' },
  otp: { 401: 'รหัสไม่ถูกต้อง ลองใหม่อีกครั้ง', 429: 'ลองบ่อยเกินไปหรือบัญชีถูกล็อกชั่วคราว กรุณาลองใหม่ภายหลัง', 503: 'ระบบยืนยันตัวตนไม่พร้อมใช้งานชั่วคราว' },
};
const FALLBACK = 'เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง';
// สถานะที่แปลว่า challenge ใช้ต่อไม่ได้แล้ว ต้องเริ่ม login ใหม่
const RESTART = new Set([404, 409, 410, 429]);

function setMsg(id, text) {
  const box = $(id);
  box.hidden = !text;
  box.querySelector('span').textContent = text || '';
}

function clearMessages() {
  ['err-login', 'err-verify', 'err-invite', 'err-enroll', 'err-app'].forEach((id) => setMsg(id, ''));
}

/* ---------- สลับหน้า ---------- */
function showAuth(name) {
  $('app-view').hidden = true;
  $('auth-view').hidden = false;
  VIEWS.forEach((v) => ($(v).hidden = v !== name));
  const current = STEP_OF[name];
  document.querySelectorAll('#steps li').forEach((li) => {
    const n = Number(li.dataset.step);
    if (n === current) li.className = 'on';
    else li.className = n < current ? 'done' : '';
  });
  document.title = (name === 's-login' ? 'เข้าสู่ระบบ' : 'ยืนยันตัวตน') + ' · kc-mfa';
  const first = $(name).querySelector('input');
  if (first) first.focus();
}

function showApp() {
  $('auth-view').hidden = true;
  $('app-view').hidden = false;
  document.title = 'แดชบอร์ด · kc-mfa';
}

function backToLogin(message) {
  $('invite').value = '';
  resetOtp('otp-verify');
  resetOtp('otp-enroll');
  clearEnrollView();
  clearMessages();
  showAuth('s-login');
  if (message) setMsg('err-login', message);
}

/* ---------- เรียก backend ---------- */
async function post(path, body) {
  const res = await fetch('/api/auth' + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(res.statusText);
    err.status = res.status;
    throw err;
  }
  return data;
}

// ปุ่มหมุนระหว่างรอ + กันกดซ้ำ
async function busy(button, fn) {
  const label = button.textContent;
  button.disabled = true;
  button.replaceChildren(Object.assign(document.createElement('span'), { className: 'spin' }));
  button.setAttribute('aria-label', 'กำลังดำเนินการ');
  try {
    return await fn();
  } finally {
    button.disabled = false;
    button.removeAttribute('aria-label');
    button.textContent = label;
  }
}

/* ---------- ช่องกรอก OTP 6 หลัก ---------- */
function buildOtp(id, onComplete) {
  const box = $(id);
  box.replaceChildren();
  for (let i = 0; i < OTP_LENGTH; i++) {
    const input = document.createElement('input');
    input.type = 'text';
    input.inputMode = 'numeric';
    input.maxLength = 1;
    input.autocomplete = i === 0 ? 'one-time-code' : 'off';
    input.setAttribute('aria-label', 'หลักที่ ' + (i + 1));
    box.appendChild(input);
  }
  const inputs = [...box.children];
  const code = () => inputs.map((x) => x.value).join('');
  const fill = (digits, from) => {
    digits.split('').slice(0, OTP_LENGTH - from).forEach((d, k) => (inputs[from + k].value = d));
    const next = Math.min(from + digits.length, OTP_LENGTH - 1);
    inputs[next].focus();
    if (code().length === OTP_LENGTH) onComplete();
  };

  inputs.forEach((input, i) => {
    input.addEventListener('input', () => {
      box.classList.remove('bad');
      const digits = input.value.replace(/\D/g, '');
      input.value = '';
      if (digits) fill(digits, i);
    });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !input.value && i > 0) {
        inputs[i - 1].value = '';
        inputs[i - 1].focus();
      } else if (e.key === 'ArrowLeft' && i > 0) {
        inputs[i - 1].focus();
      } else if (e.key === 'ArrowRight' && i < OTP_LENGTH - 1) {
        inputs[i + 1].focus();
      }
    });
    input.addEventListener('paste', (e) => {
      e.preventDefault();
      const digits = (e.clipboardData.getData('text') || '').replace(/\D/g, '');
      if (digits) fill(digits, 0);
    });
    input.addEventListener('focus', () => input.select());
  });
}

function otpCode(id) {
  return [...$(id).children].map((x) => x.value).join('');
}

function resetOtp(id, focus) {
  const box = $(id);
  [...box.children].forEach((x) => (x.value = ''));
  box.classList.remove('bad');
  if (focus && box.firstChild) box.firstChild.focus();
}

function failOtp(id) {
  const box = $(id);
  box.classList.add('bad', 'shake');
  setTimeout(() => box.classList.remove('shake'), 400);
  [...box.children].forEach((x) => (x.value = ''));
  box.firstChild.focus();
}

/* ---------- QR ---------- */
// ขอ QR (PNG) จาก backend ด้วย POST แล้วแสดงผ่าน blob URL (secret ไม่อยู่ใน URL)
async function showQr(otpauthUri) {
  const res = await fetch('/api/auth/qr', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: otpauthUri }),
  });
  if (!res.ok) throw new Error('สร้าง QR ไม่สำเร็จ');
  const img = $('qr');
  if (img.src.startsWith('blob:')) URL.revokeObjectURL(img.src);
  img.src = URL.createObjectURL(await res.blob());
}

function clearEnrollView() {
  const img = $('qr');
  if (img.src.startsWith('blob:')) URL.revokeObjectURL(img.src);
  img.removeAttribute('src');
  $('secret').textContent = '';
}

/* ---------- login flow ---------- */
function explain(e, kind, errId) {
  if (RESTART.has(e.status) && kind !== 'login') {
    backToLogin((MESSAGES[kind] && MESSAGES[kind][e.status]) || 'เซสชันการยืนยันหมดอายุ กรุณาเข้าสู่ระบบใหม่');
    return;
  }
  setMsg(errId, MESSAGES[kind][e.status] || FALLBACK);
}

$('toggle-pw').addEventListener('click', (e) => {
  const input = $('password');
  const show = input.type === 'password';
  input.type = show ? 'text' : 'password';
  e.currentTarget.setAttribute('aria-pressed', String(show));
  e.currentTarget.setAttribute('aria-label', show ? 'ซ่อนรหัสผ่าน' : 'แสดงรหัสผ่าน');
  e.currentTarget.querySelector('use').setAttribute('href', show ? '#i-eye-off' : '#i-eye');
});

$('s-login').addEventListener('submit', async (e) => {
  e.preventDefault();
  clearMessages();
  const username = $('username').value.trim();
  const password = $('password').value;
  if (!username || !password) return setMsg('err-login', 'กรุณากรอกชื่อผู้ใช้และรหัสผ่าน');
  try {
    const r = await busy($('btn-login'), () => post('/login', { username, password }));
    $('password').value = '';
    if (r.status === 'OK') return enterApp();                 // user ยังไม่มี MFA และ enforce=false
    if (r.status === 'MFA_REQUIRED') {
      resetOtp('otp-verify');
      return showAuth('s-verify');
    }
    if (r.status === 'ENROLL_INVITE_REQUIRED') {              // ต้องมีรหัสเชิญจาก admin ก่อนเห็น QR
      $('invite').value = '';
      return showAuth('s-invite');
    }
    if (r.status === 'ENROLL_REQUIRED') {
      await startEnroll('');
      return;
    }
    setMsg('err-login', FALLBACK);
  } catch (err) {
    explain(err, 'login', 'err-login');
  }
});

// ขอ secret/QR (inviteCode เว้นว่างได้เมื่อเว็บไม่ได้เปิด invite-required) แล้วไปหน้าสแกน
async function startEnroll(inviteCode) {
  const en = await post('/mfa/enroll/start', { inviteCode: inviteCode || null });
  $('secret').textContent = en.secret;
  await showQr(en.otpauthUri);
  resetOtp('otp-enroll');
  showAuth('s-enroll');
}

$('s-invite').addEventListener('submit', async (e) => {
  e.preventDefault();
  clearMessages();
  const code = $('invite').value.trim();
  if (!code) return setMsg('err-invite', 'กรุณาใส่รหัสเชิญ');
  try {
    await busy($('btn-invite'), () => startEnroll(code));
    $('invite').value = '';
  } catch (err) {
    explain(err, 'invite', 'err-invite');
  }
});

async function submitCode(otpId, button, path, errId) {
  clearMessages();
  const code = otpCode(otpId);
  if (code.length !== OTP_LENGTH) return setMsg(errId, 'กรุณาใส่รหัสให้ครบ 6 หลัก');
  try {
    await busy(button, () => post(path, { code }));
    enterApp();
  } catch (err) {
    if (err.status === 401) failOtp(otpId);
    explain(err, 'otp', errId);
  }
}

$('s-verify').addEventListener('submit', (e) => {
  e.preventDefault();
  submitCode('otp-verify', $('btn-verify'), '/mfa/verify', 'err-verify');
});
$('s-enroll').addEventListener('submit', (e) => {
  e.preventDefault();
  submitCode('otp-enroll', $('btn-enroll-confirm'), '/mfa/enroll/confirm', 'err-enroll');
});
document.querySelectorAll('[data-back]').forEach((b) => b.addEventListener('click', () => backToLogin()));

// กรอกครบ 6 หลักแล้วส่งอัตโนมัติ
buildOtp('otp-verify', () => $('s-verify').requestSubmit());
buildOtp('otp-enroll', () => $('s-enroll').requestSubmit());

/* ---------- แดชบอร์ด ---------- */
function fmtTime(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '-' : d.toLocaleTimeString('th-TH', { hour: '2-digit', minute: '2-digit' }) + ' น.';
}

function row(label, value) {
  const tr = document.createElement('tr');
  const th = document.createElement('th');
  const td = document.createElement('td');
  th.scope = 'row';
  th.textContent = label;
  td.textContent = value;
  td.style.wordBreak = 'break-all';
  tr.append(th, td);
  return tr;
}

function renderOrders(items) {
  const box = $('orders');
  if (!items.length) {
    box.replaceChildren(Object.assign(document.createElement('p'), { className: 'empty', textContent: 'ไม่มีรายการ' }));
    return;
  }
  const table = document.createElement('table');
  const head = table.createTHead().insertRow();
  [['รหัส', ''], ['รายการ', ''], ['จำนวนเงิน (บาท)', 'num']].forEach(([t, c]) => {
    const th = document.createElement('th');
    th.scope = 'col';
    th.className = c;
    th.textContent = t;
    head.appendChild(th);
  });
  const body = table.createTBody();
  items.forEach((o) => {
    const tr = body.insertRow();
    tr.insertCell().textContent = '#' + o.id;
    tr.insertCell().textContent = o.item;
    const amount = tr.insertCell();
    amount.className = 'num';
    amount.textContent = Number(o.amount).toLocaleString('th-TH');
  });
  box.replaceChildren(table);
}

async function getJson(path) {
  const res = await fetch(path, { credentials: 'same-origin' });
  if (!res.ok) {
    const err = new Error(res.statusText);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

async function enterApp() {
  clearEnrollView();
  showApp();
  try {
    const [me, orders] = await Promise.all([getJson('/api/me'), getJson('/api/orders')]);
    const name = me.username && me.username !== 'null' ? me.username : me.sub;
    $('hello').textContent = 'สวัสดี ' + name;
    $('avatar').textContent = name.charAt(0).toUpperCase();
    $('who-name').textContent = name;
    $('t-user').textContent = name;
    $('t-exp').textContent = fmtTime(me.expiresAt);
    $('me-rows').replaceChildren(row('Subject (sub)', me.sub), row('Issuer', me.issuer), row('หมดอายุ', me.expiresAt));
    renderOrders(orders);
    return true;
  } catch (err) {
    if (err.status === 401) {
      backToLogin('เซสชันหมดอายุ กรุณาเข้าสู่ระบบใหม่');
      return false;
    }
    setMsg('err-app', 'โหลดข้อมูลไม่สำเร็จ กรุณารีเฟรชหน้า');
    return false;
  }
}

$('btn-logout').addEventListener('click', async () => {
  await fetch('/api/auth/logout', { method: 'POST' });
  ['t-user', 't-exp', 'orders'].forEach((id) => {
    $(id).replaceChildren(Object.assign(document.createElement('div'), { className: 'skeleton' }));
  });
  $('me-rows').replaceChildren();
  backToLogin();
});

/* ---------- เริ่มต้น: ถ้ามี cookie เดิมที่ยังใช้ได้ให้ข้ามไปแดชบอร์ด ---------- */
(async () => {
  showAuth('s-login');
  try {
    const res = await fetch('/api/me', { credentials: 'same-origin' });
    if (res.ok) await enterApp();
  } catch (_) { /* ไม่มีเซสชัน: อยู่หน้า login */ }
})();
