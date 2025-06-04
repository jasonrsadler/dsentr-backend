use crate::services::smtp_mailer::Mailer;
use async_trait::async_trait;
use std::sync::Mutex;

use super::MailError;

/// A mock mailer that records sent emails for testing purposes.
#[derive(Debug, Default)]
pub struct MockMailer {
    pub sent_verification_emails: Mutex<Vec<(String, String)>>,
    pub sent_reset_emails: Mutex<Vec<(String, String)>>,
    pub fail_send: bool,
}

#[async_trait]
impl Mailer for MockMailer {
    async fn send_verification_email(&self, to: &str, token: &str) -> Result<(), MailError> {
        if self.fail_send {
            return Err(MailError::Other("mock failure".into()));
        }
        self.sent_verification_emails
            .lock()
            .unwrap()
            .push((to.to_string(), token.to_string()));
        Ok(())
    }

    async fn send_reset_email(&self, to: &str, token: &str) -> Result<(), MailError> {
        self.sent_reset_emails
            .lock()
            .unwrap()
            .push((to.to_string(), token.to_string()));
        if self.fail_send {
            Err(MailError::Other("mock fail".into()))
        } else {
            Ok(())
        }
    }
}
