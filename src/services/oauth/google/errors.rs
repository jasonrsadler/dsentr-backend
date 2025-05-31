use std::fmt;

#[derive(Debug)]
pub enum GoogleAuthError {
    MissingStateCookie,
    InvalidState,
    TokenExchangeFailed,
    InvalidTokenJson,
    UserInfoFetchFailed,
    InvalidUserInfo,
    NoEmailFound,
    UserCreationFailed,
    JwtCreationFailed,
    DbError(sqlx::Error),
}

impl fmt::Display for GoogleAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use GoogleAuthError::*;
        match self {
            MissingStateCookie => write!(f, "Missing 'oauth_state' cookie"),
            InvalidState => write!(f, "Invalid state parameter"),
            TokenExchangeFailed => write!(f, "Google token request failed"),
            InvalidTokenJson => write!(f, "Invalid token JSON"),
            UserInfoFetchFailed => write!(f, "Failed to fetch Google user info"),
            InvalidUserInfo => write!(f, "Invalid user info"),
            NoEmailFound => write!(f, "No email found in user info"),
            UserCreationFailed => write!(f, "Failed to create user"),
            JwtCreationFailed => write!(f, "Failed to create JWT"),
            DbError(err) => write!(f, "Database error: {}", err),
        }
    }
}

impl From<sqlx::Error> for GoogleAuthError {
    fn from(e: sqlx::Error) -> Self {
        GoogleAuthError::DbError(e)
    }
}
