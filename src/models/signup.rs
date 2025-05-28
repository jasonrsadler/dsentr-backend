use serde::Deserialize;

use super::user::OauthProvider;

#[derive(Deserialize)]
pub struct SignupPayload {
    pub email: String,
    pub password: String,
    pub first_name: String,
    pub last_name: String,
    pub company_name: Option<String>,
    pub country: Option<String>,
    pub tax_id: Option<String>,
    #[serde(default)]
    pub provider: Option<OauthProvider>
}
