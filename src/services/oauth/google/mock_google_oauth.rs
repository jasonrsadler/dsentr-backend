use super::{errors::GoogleAuthError, service::GoogleOAuthService};

#[derive(Default)]
pub struct MockGoogleOAuth {
    pub token: String,
    pub user_info: serde_json::Value,
}

#[async_trait::async_trait]
impl GoogleOAuthService for MockGoogleOAuth {
    async fn exchange_code_for_token(&self, _code: &str) -> Result<String, GoogleAuthError> {
        Ok(self.token.clone())
    }

    async fn fetch_user_info(
        &self,
        _access_token: &str,
    ) -> Result<serde_json::Value, GoogleAuthError> {
        Ok(self.user_info.clone())
    }
}
