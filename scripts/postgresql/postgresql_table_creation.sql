CREATE TABLE credential (
    credential_id bytea PRIMARY KEY,
    user_handle bytea NOT NULL,
    user_name varchar(64) NOT NULL,
    user_display_name varchar(64) NOT NULL,
    credential_public_key_json varchar(2048) NOT NULL,
    sign_count bigint NOT NULL,
    transports varchar(50) NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NULL,
    last_used_at timestamptz NULL
);

CREATE INDEX ix_credential_user_name ON credential (user_name);