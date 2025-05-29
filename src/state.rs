use crate::db::user_repository::UserRepository;
use crate::services::smtp_mailer::Mailer;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<dyn UserRepository>,
    pub mailer: Arc<dyn Mailer>,
}
