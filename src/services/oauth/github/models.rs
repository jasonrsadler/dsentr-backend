// services/oauth/github/models.rs
use serde::Deserialize;

#[derive(Deserialize)]
pub struct GitHubCallback {
    pub code: String,
    pub state: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct GitHubToken {
    pub access_token: String,
}
