use core::fmt;

use serde::{Deserialize, Serialize};
use sqlx::{prelude::Type, FromRow};

#[derive(sqlx::Type, Debug, Deserialize, Serialize, PartialEq, Eq, Copy, Clone)]
#[sqlx(type_name = "oauth_provider", rename_all = "lowercase")] // match your PostgreSQL type
#[serde(rename_all = "lowercase")] // <- Ensures it matches JSON like "google"
pub enum OauthProvider {
    Google,
    Github,
    Apple,
    Email,
}

impl fmt::Display for OauthProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            OauthProvider::Google => "Google",
            OauthProvider::Github => "GitHub",
            OauthProvider::Apple => "Apple",
            OauthProvider::Email => "Email",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "user_role")] // Matches the Postgres enum name
#[sqlx(rename_all = "lowercase")] // Ensures matching strings
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
    pub oauth_provider: Option<OauthProvider>,
    pub created_at: time::OffsetDateTime,
}

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow)]
pub struct PublicUser {
    pub id: uuid::Uuid,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub role: Option<UserRole>,
    pub plan: Option<String>,
    pub company_name: Option<String>,
}
