use serde::Serialize;
use axum::{http::StatusCode, response::{IntoResponse, Redirect}, Json};

#[derive(Serialize)]
pub struct JsonResponse {
    pub status: String,
    pub success: bool,
    pub message: String,
}

impl JsonResponse {
    pub fn success(msg: &str) -> impl IntoResponse {
        (
            StatusCode::OK,
            Json(JsonResponse {
                status: "success".to_string(),
                success: true,
                message: msg.to_string(),
            }),
        )
    }

    pub fn conflict(msg: &str) -> impl IntoResponse {
        (
            StatusCode::CONFLICT,
            Json(JsonResponse {
                status: "error".to_string(),
                success: false,
                message: msg.to_string(),
            }),
        )
    }

    pub fn server_error(msg: &str) -> impl IntoResponse {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(JsonResponse {
                status: "error".to_string(),
                success: false,
                message: msg.to_string(),
            }),
        )
    }

    pub fn unauthorized(msg: &str) -> impl IntoResponse {
        (
            StatusCode::UNAUTHORIZED,
            Json(JsonResponse {
                status: "error".to_string(),
                success: false,
                message: msg.to_string(),
            })
        )
    }

    pub fn bad_request(msg: &str) -> impl IntoResponse {
        (
            StatusCode::BAD_REQUEST,
            Json(JsonResponse {
                status: "error".to_string(),
                success: false,
                message: msg.to_string(),
            }),
        )
    }

    pub fn too_many_requests(msg: &str) -> impl IntoResponse {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(JsonResponse {
                status: "error".to_string(),
                success: false,
                message: msg.to_string(),
            }),
        )
    }

    pub fn redirect_to_login_with_error(msg: &str) -> impl IntoResponse {
        let frontend_url = std::env::var("FRONTEND_ORIGIN").unwrap_or_else(|_| "https://localhost:5173".to_string());
        let redirect_url = format!("{}/login?error={}", frontend_url, urlencoding::encode(msg));
        Redirect::to(&redirect_url).into_response()
    }
}