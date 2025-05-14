use serde::Serialize;
use axum::{http::StatusCode, response::IntoResponse, Json};

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

    pub fn success_json(data: serde_json::Value) -> impl IntoResponse {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "success": true, "data": data })),
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
}