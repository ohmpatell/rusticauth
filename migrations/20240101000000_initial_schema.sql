-- ... (existing tables)

-- Add revocation tracking to refresh_tokens
ALTER TABLE refresh_tokens ADD COLUMN revoked_at TIMESTAMP WITH TIME ZONE;

-- Index for faster revocation checks
CREATE INDEX idx_refresh_tokens_revoked_at ON refresh_tokens(revoked_at);