-- NULL means the account has no password and signs in through a provider only.
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

-- One row per linked provider account. Users are matched by the provider's
-- stable id, never by email alone, because a provider email can change.
CREATE TABLE user_identities (
    id               UUID PRIMARY KEY,
    user_id          UUID         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider         VARCHAR(32)  NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uk_user_identities_provider_subject UNIQUE (provider, provider_user_id)
);
