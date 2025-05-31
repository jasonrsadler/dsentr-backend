use crate::services::oauth::google::{errors::GoogleAuthError, service::GoogleOAuthService};
use async_trait::async_trait;
use reqwest::Client;
use serde_json::Value;

pub struct GoogleOAuthClient {
    pub client: Client,
}

#[async_trait]
impl GoogleOAuthService for GoogleOAuthClient {
    async fn exchange_code_for_token(&self, code: &str) -> Result<String, GoogleAuthError> {
        let res = self
            .client
            .post(std::env::var("GOOGLE_ACCOUNTS_OAUTH_TOKEN_CLIENT_URL").unwrap())
            .form(&[
                ("code", code),
                ("client_id", &std::env::var("GOOGLE_CLIENT_ID").unwrap()),
                (
                    "client_secret",
                    &std::env::var("GOOGLE_CLIENT_SECRET").unwrap(),
                ),
                (
                    "redirect_uri",
                    &std::env::var("GOOGLE_REDIRECT_URI").unwrap(),
                ),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|_| GoogleAuthError::TokenExchangeFailed)?;

        if !res.status().is_success() {
            return Err(GoogleAuthError::TokenExchangeFailed);
        }

        let token_json: Value = res
            .json()
            .await
            .map_err(|_| GoogleAuthError::InvalidTokenJson)?;
        token_json["access_token"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or(GoogleAuthError::InvalidTokenJson)
    }

    async fn fetch_user_info(&self, access_token: &str) -> Result<Value, GoogleAuthError> {
        let res = self
            .client
            .get(std::env::var("GOOGLE_ACCOUNTS_OAUTH_USER_INFO_URL").unwrap())
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|_| GoogleAuthError::UserInfoFetchFailed)?;

        if !res.status().is_success() {
            return Err(GoogleAuthError::UserInfoFetchFailed);
        }

        res.json()
            .await
            .map_err(|_| GoogleAuthError::InvalidUserInfo)
    }
}
