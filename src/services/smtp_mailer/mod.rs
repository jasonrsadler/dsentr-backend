use async_trait::async_trait;

#[derive(Debug)]
pub enum MailError {
    Other(String),
    InvalidEmailAddress(String),
    SendError(String),
    EnvVarMissing(String),
}

use std::fmt;

impl fmt::Display for MailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MailError::Other(e) => write!(f, "Error: {}", e),
            MailError::InvalidEmailAddress(e) => write!(f, "Invalid Address: {}", e),
            MailError::SendError(e) => write!(f, "Send error: {}", e),
            MailError::EnvVarMissing(e) => write!(f, "Env Var Missing: {}", e),
        }
    }
}

use lettre::transport::smtp::Error as SmtpError;

impl From<SmtpError> for MailError {
    fn from(err: SmtpError) -> Self {
        MailError::SendError(err.to_string())
    }
}

impl From<std::env::VarError> for MailError {
    fn from(err: std::env::VarError) -> Self {
        MailError::EnvVarMissing(err.to_string())
    }
}

impl From<lettre::error::Error> for MailError {
    fn from(err: lettre::error::Error) -> Self {
        MailError::SendError(err.to_string())
    }
}

impl From<AddressError> for MailError {
    fn from(e: AddressError) -> Self {
        MailError::InvalidEmailAddress(e.to_string())
    }
}

#[async_trait]
pub trait Mailer: Send + Sync {
    async fn send_verification_email(&self, to: &str, token: &str) -> Result<(), MailError>;
    async fn send_reset_email(&self, to: &str, token: &str) -> Result<(), MailError>;
}

mod mock_mailer;
mod smtp_mailer;

use lettre::address::AddressError;
#[allow(unused_imports)]
pub use mock_mailer::MockMailer;
pub use smtp_mailer::SmtpMailer;
