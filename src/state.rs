use crate::db::user_repository::UserRepository;
use crate::services::oauth::{
    github::service::GitHubOAuthService, google::service::GoogleOAuthService,
};
use crate::services::smtp_mailer::Mailer;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<dyn UserRepository>,
    pub mailer: Arc<dyn Mailer>,
    pub google_oauth: Arc<dyn GoogleOAuthService>,
    pub github_oauth: Arc<dyn GitHubOAuthService + Send + Sync>,
}
