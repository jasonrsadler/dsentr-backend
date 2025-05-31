// services/oauth/github/service.rs

use super::{errors::GitHubAuthError, models::GitHubToken};
use async_trait::async_trait;

#[derive(Debug, Clone, Default)]
pub struct GitHubUserInfo {
    pub email: String,
    pub first_name: String,
    pub last_name: String,
}

#[async_trait]
pub trait GitHubOAuthService: Send + Sync {
    async fn exchange_code_for_token(&self, code: &str) -> Result<GitHubToken, GitHubAuthError>;
    async fn fetch_user_info(
        &self,
        access_token: &GitHubToken,
    ) -> Result<GitHubUserInfo, GitHubAuthError>;
}
