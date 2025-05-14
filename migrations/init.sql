CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- Create the database (run this outside of psql first)
CREATE DATABASE your_database_name;


-- Connect to the database
\c your_database_name;
-- (Continue with your other table creation scripts)
CREATE TABLE IF NOT EXISTS early_access_emails (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    company_name TEXT,
    country TEXT,
    tax_id TEXT,
    stripe_customer_id TEXT,
    is_subscribed BOOLEAN NOT NULL DEFAULT false,
    plan TEXT,
    trial_ends_at TIMESTAMP WITH TIME ZONE,
    settings JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_email_verification_tokens_user_id ON email_verification_tokens(user_id);
CREATE INDEX idx_email_verification_tokens_token ON email_verification_tokens(token);
ALTER TABLE email_verification_tokens ADD COLUMN used_at TIMESTAMPTZ;
