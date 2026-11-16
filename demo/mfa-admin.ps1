<#
  เครื่องมือผู้ดูแลของชุดทดลอง: ออกรหัสเชิญให้ user ลงทะเบียน MFA ครั้งแรก หรือ reset MFA ของ user

  ใช้:
    (ไม่ต้องตั้งอะไรถ้ามี .env ที่ root ของ repo สคริปต์อ่าน MFA_ADMIN_SECRET จากไฟล์นั้นเอง
     หรือจะตั้งเองด้วย $env:MFA_ADMIN_SECRET = "..." ก็ได้ ซึ่งมีผลก่อน)
    .\demo\mfa-admin.ps1 -UserId <sub ของ user>            # ออกรหัสเชิญ (ใช้ได้ครั้งเดียว อายุ 30 นาที)
    .\demo\mfa-admin.ps1 -UserId <sub ของ user> -Reset     # ล้าง MFA เดิม แล้วออกรหัสเชิญใหม่

  sub ของ user ดูได้ที่ Keycloak admin (http://localhost:8180) > Users > เลือก user > ช่อง ID
  ส่งรหัสเชิญให้ user ผ่านช่องทางอื่นที่ไม่ใช่หน้า login (เช่นแจ้งด้วยตัวเอง) ห้ามส่งทางที่คนอื่นเห็นได้

  หมายเหตุ: ขอ token ผ่านพอร์ตของเครื่อง (8180) แต่ใส่ Host: keycloak:8080 เพื่อให้ iss ใน token ตรงกับที่ mfa-service
  เชื่อถือ (Keycloak สร้าง iss จาก Host); ส่ง secret ผ่าน stdin ไม่ใช่ argument จึงไม่โผล่ในรายการ process
#>
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9._-]{1,64}$')][string]$UserId,
    # ชื่อผู้ดูแลที่ลงใน audit log (ผู้เรียกระบุเอง ไม่ได้พิสูจน์ตัวตน) ค่าเริ่มต้น = ชื่อผู้ใช้ Windows
    [ValidatePattern('^[A-Za-z0-9@._-]{1,64}$')][string]$Actor = ($env:USERNAME -replace '[^A-Za-z0-9@._-]', '_'),
    [switch]$Reset
)

$ErrorActionPreference = 'Stop'
$secret = $env:MFA_ADMIN_SECRET
$source = 'ตัวแปร $env:MFA_ADMIN_SECRET'
if (-not $secret) {
    $source = '.env'
    # ไม่ได้ตั้งตัวแปร: อ่าน MFA_ADMIN_SECRET จาก .env ที่ root ของ repo (ไม่พิมพ์ค่าออกหน้าจอ)
    $envFile = Join-Path $PSScriptRoot '..\.env'
    if (Test-Path $envFile) {
        $line = Get-Content $envFile | Where-Object { $_ -match '^\s*MFA_ADMIN_SECRET\s*=' } | Select-Object -First 1
        if ($line) { $secret = ($line -replace '^\s*MFA_ADMIN_SECRET\s*=\s*', '').Trim().Trim('"').Trim("'") }
    }
}
if (-not $secret) { throw 'หา MFA_ADMIN_SECRET ไม่เจอ: ใส่ค่าใน .env ที่ root ของ repo หรือตั้ง $env:MFA_ADMIN_SECRET ก่อนรัน' }

# PowerShell ต่อ newline ท้ายข้อความที่ pipe เข้า curl: ถ้า client_secret เป็นพารามิเตอร์สุดท้าย
# newline จะติดไปกับค่า secret แล้ว Keycloak ตอบ unauthorized_client จึงปิดท้ายด้วยพารามิเตอร์ที่ไม่ใช้ (_)
$form = 'grant_type=client_credentials&client_id=mfa-admin&client_secret=' + [uri]::EscapeDataString($secret) + '&_=1'
# -sS = ไม่แสดง progress แต่แสดง error ของ curl (เช่น ต่อพอร์ตไม่ติด) ; -w ต่อท้ายด้วยรหัส HTTP
$raw = $form | curl.exe -sS -X POST 'http://localhost:8180/realms/brand-a/protocol/openid-connect/token' `
    -H 'Host: keycloak:8080' --data-binary '@-' -w "`nHTTP:%{http_code}" 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
    throw "curl ต่อ Keycloak ที่ localhost:8180 ไม่ได้ (exit $LASTEXITCODE): $raw`nเช็กว่า 'docker compose ps' แสดง keycloak เป็น healthy แล้ว"
}
$body, $code = $raw -split "`nHTTP:", 2
$token = $null
try { $token = ($body | ConvertFrom-Json).access_token } catch { }
if (-not $token) {
    # ตัดข้อมูลที่อาจเป็น token ออก แสดงเฉพาะรหัส HTTP กับ error ของ Keycloak
    $err = try { ($body | ConvertFrom-Json) | Select-Object error, error_description | Out-String } catch { $body }
    # ลายนิ้วมือ = SHA-256 แค่ 8 ตัวแรก (ย้อนกลับเป็น secret ไม่ได้) ไว้เทียบกับค่าที่ container ของ Keycloak ได้รับ:
    #   docker compose exec keycloak bash -c 'printf %s "$MFA_ADMIN_SECRET" | sha256sum | cut -c1-8'
    $sha = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($secret))
    $fp = ([BitConverter]::ToString($sha, 0, 4) -replace '-', '').ToLower()
    throw "ขอ token ไม่สำเร็จ (HTTP $($code.Trim())): $err`nsecret ที่สคริปต์ใช้มาจาก: $source ยาว $($secret.Length) ตัวอักษร ลายนิ้วมือ $fp"
}

$base = "http://localhost:8090/v1/users/$UserId/mfa"
if ($Reset) {
    curl.exe -s -o NUL -w "reset: HTTP %{http_code}`n" -X DELETE $base -H "Authorization: Bearer $token" -H "X-Admin-Actor: $Actor"
}
$resp = curl.exe -s -w "`nHTTP %{http_code}" -X POST "$base/invite" -H "Authorization: Bearer $token" -H "X-Admin-Actor: $Actor"
Write-Output $resp
