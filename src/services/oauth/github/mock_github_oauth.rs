use async_trait::async_trait;

use crate::services::oauth::github::{
    errors::GitHubAuthError, models::GitHubToken, service::GitHubOAuthService,
    service::GitHubUserInfo,
};

#[derive(Default)]
pub struct MockGitHubOAuth {
    pub token: GitHubToken,
    pub user_info: GitHubUserInfo,
}

#[async_trait]
impl GitHubOAuthService for MockGitHubOAuth {
    async fn exchange_code_for_token(&self, _code: &str) -> Result<GitHubToken, GitHubAuthError> {
        Ok(self.token.clone())
    }

    async fn fetch_user_info(
        &self,
        _token: &GitHubToken,
    ) -> Result<GitHubUserInfo, GitHubAuthError> {
        Ok(self.user_info.clone())
    }
}
