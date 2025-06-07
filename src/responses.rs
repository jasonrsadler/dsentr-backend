use axum::{
    http::StatusCode,
    response::{IntoResponse, Redirect},
    Json,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
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
            }),
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
        let frontend_url = std::env::var("FRONTEND_ORIGIN")
            .unwrap_or_else(|_| "https://localhost:5173".to_string());
        let redirect_url = format!("{}/login?error={}", frontend_url, urlencoding::encode(msg));
        Redirect::to(&redirect_url).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse;
    use serde_json::from_slice;

    use crate::responses::JsonResponse;

    #[tokio::test]
    async fn test_success_response() {
        let resp = JsonResponse::success("ok").into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: JsonResponse = from_slice(&body).unwrap();
        assert_eq!(json.status, "success");
        assert!(json.success);
        assert_eq!(json.message, "ok");
    }

    #[tokio::test]
    async fn test_redirect_to_login_with_error() {
        std::env::set_var("FRONTEND_ORIGIN", "https://example.com");
        let resp = JsonResponse::redirect_to_login_with_error("token expired").into_response();
        println!("{}", std::any::type_name_of_val(&resp));
        assert_eq!(resp.status(), axum::http::StatusCode::SEE_OTHER);

        if let Some(loc) = resp.headers().get("location") {
            let loc_str = loc.to_str().unwrap();
            assert!(loc_str.starts_with("https://example.com/login?error="));
            assert!(loc_str.contains("token%20expired"));
        } else {
            panic!("Redirect did not contain a location header");
        }
    }
}
