-- PostgreSQL: ตารางของ mfa-service (ต้องตรงกับ entity MfaCredential / MfaPending เพราะ ddl-auto = validate)

create table mfa_credential (
    id              varchar(300) primary key,       -- realm|userId
    realm           varchar(128) not null,
    user_id         varchar(64)  not null,
    secret_enc      varchar(512) not null,          -- AES-256-GCM (base64)
    last_used_step  bigint       not null,
    failed_attempts integer      not null,
    locked_until    timestamp(6) with time zone,
    created_at      timestamp(6) with time zone not null
);

create table mfa_pending (
    id          varchar(300) primary key,           -- realm|userId
    secret_enc  varchar(512) not null,
    expires_at  timestamp(6) with time zone not null,
    attempts    integer      not null
);

-- ใช้ลบ pending ที่หมดอายุเป็นรอบ
create index mfa_pending_expires_at_idx on mfa_pending (expires_at);
