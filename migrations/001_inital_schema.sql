-- migrations/20240101000000_initial_schema.sql
-- This creates our core tables for OAuth2/OIDC

-- Users table: stores people who can authenticate
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- OAuth clients: applications that want to use our auth server
CREATE TABLE oauth_clients (
    id SERIAL PRIMARY KEY,
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_secret TEXT NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    redirect_uris TEXT[] NOT NULL, -- PostgreSQL array of allowed redirect URIs
    scope TEXT DEFAULT 'openid profile', -- default scopes this client can request
    is_confidential BOOLEAN DEFAULT TRUE, -- public clients (mobile apps) vs confidential (server apps)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Authorization codes: temporary codes in OAuth flow
CREATE TABLE auth_codes (
    code VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    code_challenge TEXT, -- for PKCE (security extension)
    code_challenge_method VARCHAR(10), -- S256 or plain
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Refresh tokens: long-lived tokens for getting new access tokens
CREATE TABLE refresh_tokens (
    token VARCHAR(255) PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    scope TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_auth_codes_expires_at ON auth_codes(expires_at);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX idx_auth_codes_user_id ON auth_codes(user_id);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);