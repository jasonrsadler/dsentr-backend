use lettre::{
    message::Mailbox,
    transport::smtp::{authentication::Credentials, client::{Tls, TlsParameters}},
    AsyncSmtpTransport, Tokio1Executor, Message, AsyncTransport,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct Mailer {
    transport: Arc<AsyncSmtpTransport<Tokio1Executor>>,
    sender: Mailbox,
}

impl Mailer {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let host = std::env::var("SMTP_HOST")?;
        let username = std::env::var("SMTP_USERNAME")?;
        let password = std::env::var("SMTP_PASSWORD")?;
        let from = std::env::var("SMTP_FROM")?.parse()?;
        let port: u16 = std::env::var("SMTP_PORT")?.parse()?;

        let disabled_tls = std::env::var("SMTP_TLS_DISABLED")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase() == "true";

       
        let mailer = if disabled_tls {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&host)
                .port(port)
                .build()
        } else {
            let creds = Credentials::new(
                username,
                password,
            );

            let tls = TlsParameters::new(host.clone())?;
            AsyncSmtpTransport::<Tokio1Executor>::relay(&host)?
                .port(port)
                .tls(Tls::Required(tls))
                .credentials(creds)
                .build()
        };

        Ok(Mailer {
            transport: Arc::new(mailer),
            sender: from,
        })
    }

    pub async fn send_verification_email(
        &self,
        to: &str,
        token: &str,
    ) -> Result<(), Box<dyn  std::error::Error + Send + Sync>> {
        let dev_mode = std::env::var("DEV_MODE")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase() == "true";
        let verify_link = if dev_mode {
            std::env::var("FRONTEND_ORIGIN").unwrap() + 
            &std::env::var("EMAIL_VERIFICATION_PATH").unwrap()
        } else {
           std::env::var("FRONTEND_ORIGIN_PROD").unwrap() + 
           &std::env::var("EMAIL_VERIFICATION_PATH").unwrap()
        };
        let email = Message::builder()
            .from(self.sender.clone())
            .to(to.parse()?)
            .subject("Verify your email")
            .body(format!(
                "Thanks for signing up!\n\nVerify here:\n{}{}",
                verify_link,
                token
            ))?;

        self.transport.send(email).await.map(|_| ()).map_err(|e| e.into())
    }

    
}