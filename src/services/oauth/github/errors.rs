// services/oauth/github/errors.rs
use std::fmt;

#[derive(Debug)]
pub enum GitHubAuthError {
    MissingStateCookie,
    InvalidState,
    TokenExchangeFailed,
    InvalidTokenJson,
    UserInfoFetchFailed,
    InvalidUserInfo,
    EmailFetchFailed,
    NoVerifiedEmail,
    UserCreationFailed,
    JwtCreationFailed,
    DbError(sqlx::Error),
}

impl fmt::Display for GitHubAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use GitHubAuthError::*;
        match self {
            MissingStateCookie => write!(f, "Missing 'oauth_state' cookie"),
            InvalidState => write!(f, "Invalid state parameter"),
            TokenExchangeFailed => write!(f, "GitHub token exchange failed"),
            InvalidTokenJson => write!(f, "Invalid GitHub token"),
            UserInfoFetchFailed => write!(f, "Failed to fetch GitHub user info"),
            InvalidUserInfo => write!(f, "Invalid GitHub user info"),
            EmailFetchFailed => write!(f, "Failed to fetch GitHub email"),
            NoVerifiedEmail => write!(f, "No verified GitHub email found"),
            UserCreationFailed => write!(f, "User creation failed"),
            JwtCreationFailed => write!(f, "JWT generation failed"),
            DbError(err) => write!(f, "Database error: {}", err),
        }
    }
}

impl From<sqlx::Error> for GitHubAuthError {
    fn from(err: sqlx::Error) -> Self {
        GitHubAuthError::DbError(err)
    }
}
