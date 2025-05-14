use axum::{extract::{Json, State}, response::{IntoResponse, Response}};
use serde::Deserialize;
use crate::state::AppState;
use crate::responses::JsonResponse;

#[derive(Deserialize)]
pub struct EarlyAccessPayload {
    pub email: String,
}

pub async fn handle_early_access(
    State(state): State<AppState>,
    Json(payload): Json<EarlyAccessPayload>,
) -> Response {
    
    let pool = &state.db;
    let result = sqlx::query("INSERT INTO early_access_emails (email) VALUES ($1)")
        .bind(&payload.email)
        .execute(pool)
        .await;

    match result {
        Ok(_) => JsonResponse::success("Thanks for signing up!").into_response(),
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            eprintln!("unique violation insert error: {:?}", db_err.to_string());
            JsonResponse::conflict("You're already on the list!").into_response()
        }
        Err(e) => {
            eprintln!("insert error: {:?}", e.to_string());
            JsonResponse::server_error("Something went wrong").into_response()
        }
    }
}
