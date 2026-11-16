-- รหัสเชิญสำหรับลงทะเบียน MFA ครั้งแรก: ออกโดย admin (client ที่ admin: true) ใช้ได้ครั้งเดียว
-- เก็บเฉพาะ hash; ต้องตรงกับ entity MfaInvite เพราะ ddl-auto = validate
create table mfa_invite (
    id          varchar(300) primary key,           -- realm|userId
    code_hash   varchar(64)  not null,              -- SHA-256 (hex) ของ id + ":" + รหัส
    expires_at  timestamp(6) with time zone not null,
    attempts    integer      not null
);

create index mfa_invite_expires_at_idx on mfa_invite (expires_at);
