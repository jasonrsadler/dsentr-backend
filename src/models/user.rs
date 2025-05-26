use serde::{Deserialize, Serialize};
use sqlx::{prelude::Type, FromRow};

use crate::routes::auth::signup::OauthProvider;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "user_role")]       // Matches the Postgres enum name
#[sqlx(rename_all = "lowercase")]      // Ensures matching strings
pub enum UserRole {
    User,
    Admin,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: uuid::Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub first_name: String,
    pub last_name: String,
    pub role: Option<UserRole>,
    pub plan: Option<String>,
    pub company_name: Option<String>,
    pub oauth_provider: Option<OauthProvider>
}

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow)]
pub struct PublicUser {
    pub id: uuid::Uuid,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub role: Option<UserRole>,
    pub plan: Option<String>,
    pub company_name: Option<String>
}
