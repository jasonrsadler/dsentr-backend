use crate::{
    db::user_repository::UserRepository, models::{
        signup::SignupPayload, 
        user::{
            OauthProvider, 
            PublicUser, 
            User, 
            UserRole
        }
    }
};
use async_trait::async_trait;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::user_repository::UserId;

pub struct PostgresUserRepository {
    pub pool: PgPool,
}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn find_user_id_by_email(&self, email: &str) -> Result<Option<UserId>, anyhow::Error> {
        let rec = sqlx::query!("SELECT id FROM users WHERE email = $1", email)
            .fetch_optional(&self.pool)
            .await?;

        Ok(rec.map(|r| UserId { id: r.id }))
    }

    async fn insert_password_reset_token(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), anyhow::Error> {
        sqlx::query!(
            "INSERT INTO password_resets (user_id, token, expires_at)
            VALUES ($1, $2, $3)",
            user_id,
            token,
            expires_at
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, anyhow::Error> {
        let row = sqlx::query_as!(
            User,
            r#"
            SELECT id, email, role as "role: _", password_hash, first_name, last_name, plan, company_name,  oauth_provider as "oauth_provider: OauthProvider"
            FROM users
            WHERE email = $1
            "#,
            email
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    async fn create_user_with_oauth(
        &self,
        email: &str,
        first_name: &str,
        last_name: &str,
        provider: OauthProvider,
    ) -> Result<User, anyhow::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (
                email,
                password_hash,
                first_name,
                last_name,
                oauth_provider,
                is_verified,
                role
            )
            VALUES ($1, '', $2, $3, $4::oauth_provider, true, 'user'::user_role)
            RETURNING
                id,
                email,
                password_hash,
                first_name,
                last_name,
                role as "role: UserRole",
                plan,
                company_name,
                oauth_provider as "oauth_provider: OauthProvider"
            "#,
            email,
            first_name,
            last_name,
            provider as OauthProvider
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(user)
    }

    async fn find_public_user_by_id(&self, user_id: Uuid) -> Result<Option<PublicUser>, anyhow::Error> {
        sqlx::query_as::<_, PublicUser>(
            r#"
            SELECT id, email, first_name, last_name, role, plan, company_name
            FROM users
            WHERE id = $1
            "#
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    async fn verify_password_reset_token(&self, token: &str) -> Result<Option<Uuid>, anyhow::Error> {
        let result = sqlx::query!(
            r#"
            SELECT user_id FROM password_resets
            WHERE token = $1 AND expires_at > $2 AND used_at IS NULL
            "#,
            token,
            OffsetDateTime::now_utc()
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(|r| r.user_id))
    }

    async fn update_user_password(&self, user_id: Uuid, password_hash: &str) -> Result<(), anyhow::Error> {
        sqlx::query!(
            "UPDATE users SET password_hash = $1 WHERE id = $2",
            password_hash,
            user_id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn mark_password_reset_token_used(&self, token: &str) -> Result<(), anyhow::Error> {
        sqlx::query!(
            "UPDATE password_resets SET used_at = $1 WHERE token = $2",
            OffsetDateTime::now_utc(),
            token
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn is_email_taken(&self, email: &str) -> Result<bool, sqlx::Error> {
        let res = sqlx::query_scalar!("SELECT 1 FROM users WHERE email = $1", email)
            .fetch_optional(&self.pool)
            .await?;
        Ok(res.is_some())
    }

    async fn create_user(
        &self,
        payload: &SignupPayload,
        password_hash: &str,
        provider: OauthProvider,
    ) -> Result<Uuid, sqlx::Error> {
        sqlx::query_scalar!(
            r#"
            INSERT INTO users (
                email, password_hash, first_name, last_name, company_name, country, tax_id,
                is_verified, is_subscribed, settings, created_at, updated_at, oauth_provider
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7,
                false, false, '{}', now(), now(), $8::oauth_provider
            )
            RETURNING id
            "#,
            payload.email,
            password_hash,
            payload.first_name,
            payload.last_name,
            payload.company_name,
            payload.country,
            payload.tax_id,
            provider as OauthProvider
        )
        .fetch_one(&self.pool)
        .await
    }

    async fn insert_verification_token(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
            user_id,
            token,
            expires_at
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
    }

    async fn cleanup_user_and_token(&self, user_id: Uuid, token: &str) -> Result<(), sqlx::Error> {
        let _ = sqlx::query!(
            "DELETE FROM email_verification_tokens WHERE token = $1",
            token
        )
        .execute(&self.pool)
        .await;

        let _ = sqlx::query!(
            "DELETE FROM users WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await;

        Ok(())
    }

    async fn mark_verification_token_used(&self, token: &str, now: OffsetDateTime) -> Result<Option<Uuid>, sqlx::Error> {
        let rec = sqlx::query!(
            r#"
            UPDATE email_verification_tokens
            SET used_at = $1
            WHERE token = $2
              AND expires_at > $1
              AND used_at IS NULL
            RETURNING user_id
            "#,
            now,
            token
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(rec.map(|r| r.user_id))
    }

    async fn set_user_verified(&self, user_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "UPDATE users SET is_verified = true WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_early_access_email(&self, email: &str) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO early_access_emails (email) VALUES ($1)")
            .bind(email)
            .execute(&self.pool)
            .await
            .map(|_| ()) // return `Ok(())` on success
    }
}
