CREATE TYPE oauth_provider AS ENUM ('google', 'github', 'apple');
ALTER TABLE users ADD COLUMN oauth_provider oauth_provider;
