use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::models::{
    signup::SignupPayload,
    user::{OauthProvider, PublicUser, User},
};

pub struct UserId {
    pub id: Uuid,
}

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_user_id_by_email(&self, email: &str) -> Result<Option<UserId>, sqlx::Error>;
    async fn insert_password_reset_token(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), sqlx::Error>;
    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, sqlx::Error>;
    async fn create_user_with_oauth(
        &self,
        email: &str,
        first_name: &str,
        last_name: &str,
        provider: OauthProvider,
    ) -> Result<User, sqlx::Error>;
    async fn find_public_user_by_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<PublicUser>, sqlx::Error>;
    async fn verify_password_reset_token(&self, token: &str) -> Result<Option<Uuid>, sqlx::Error>;
    async fn update_user_password(
        &self,
        user_id: Uuid,
        password_hash: &str,
    ) -> Result<(), sqlx::Error>;
    async fn mark_password_reset_token_used(&self, token: &str) -> Result<(), sqlx::Error>;
    async fn is_email_taken(&self, email: &str) -> Result<bool, sqlx::Error>;
    async fn create_user(
        &self,
        payload: &SignupPayload,
        password_hash: &str,
        provider: OauthProvider,
    ) -> Result<Uuid, sqlx::Error>;
    async fn insert_verification_token(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), sqlx::Error>;
    async fn cleanup_user_and_token(&self, user_id: Uuid, token: &str) -> Result<(), sqlx::Error>;
    async fn mark_verification_token_used(
        &self,
        token: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Uuid>, sqlx::Error>;
    async fn set_user_verified(&self, user_id: Uuid) -> Result<(), sqlx::Error>;
    async fn insert_early_access_email(&self, email: &str) -> Result<(), sqlx::Error>;
}
