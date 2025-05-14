-- migrations/2025-05-12-01_add_is_verified.sql

ALTER TABLE users
ADD COLUMN is_verified BOOLEAN NOT NULL DEFAULT FALSE;
