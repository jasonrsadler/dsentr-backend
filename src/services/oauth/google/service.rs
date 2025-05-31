use crate::services::oauth::google::errors::GoogleAuthError;
use async_trait::async_trait;
use serde_json::Value;

#[async_trait]
pub trait GoogleOAuthService: Send + Sync {
    async fn exchange_code_for_token(&self, code: &str) -> Result<String, GoogleAuthError>;
    async fn fetch_user_info(&self, access_token: &str) -> Result<Value, GoogleAuthError>;
}
