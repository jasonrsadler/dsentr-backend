use crate::utils::email::Mailer;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub mailer: Arc<Mailer>,
}
