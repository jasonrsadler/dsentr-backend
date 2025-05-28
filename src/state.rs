use std::sync::Arc;
use crate::{db::user_repository::UserRepository, utils::email::Mailer};

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<dyn UserRepository>,
    pub mailer: Arc<Mailer>,
}
