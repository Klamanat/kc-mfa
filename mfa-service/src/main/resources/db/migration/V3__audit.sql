-- audit log ของ mfa-service (เพิ่มอย่างเดียว ไม่แก้/ลบ): เหตุการณ์ของ admin และการลงทะเบียน MFA
-- ต้องตรงกับ entity MfaAudit เพราะ ddl-auto = validate
-- production: ให้ user ของ service นี้มีสิทธิ์ INSERT/SELECT บนตารางนี้เท่านั้น (ไม่ให้ UPDATE/DELETE) และส่งออกไปเก็บที่อื่นด้วย
create table mfa_audit (
    id         bigserial primary key,
    at         timestamp(6) with time zone not null,
    event      varchar(40)  not null,
    realm      varchar(128) not null,
    user_id    varchar(64)  not null,
    client_id  varchar(128) not null,
    actor      varchar(64),                          -- ค่า X-Admin-Actor (ผู้ดูแลแจ้งเอง ไม่ได้พิสูจน์ตัวตน)
    remote_ip  varchar(64),
    detail     varchar(200)
);

create index mfa_audit_event_client_at_idx on mfa_audit (event, client_id, at);
create index mfa_audit_user_idx on mfa_audit (realm, user_id, at);
