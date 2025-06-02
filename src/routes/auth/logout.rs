use axum::{
    http::{header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use time::Duration as TimeDuration;

use crate::responses::JsonResponse;

pub async fn handle_logout() -> impl IntoResponse {
    let expired_cookie = Cookie::build(("auth_token", ""))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(TimeDuration::seconds(0));
    // Set the Set-Cookie header
    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&expired_cookie.to_string()).unwrap(),
    );

    (StatusCode::OK, headers, JsonResponse::success("Logged out"))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
        routing::post,
        Router,
    };
    use serde_json::Value;
    use std::usize;
    use tower::ServiceExt; // for `app.oneshot(...)`

    use crate::routes::auth::logout::handle_logout;

    #[tokio::test]
    async fn test_logout_clears_auth_cookie_and_returns_success() {
        // Build the app with only the /logout route
        let app = Router::new().route("/logout", post(handle_logout));

        // Simulate the POST request
        let res = app
            .oneshot(
                Request::post("/logout")
                    .header("Content-Type", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Check status
        assert_eq!(res.status(), StatusCode::OK);

        // Check Set-Cookie header exists
        let set_cookie_header = res.headers().get("set-cookie").unwrap().to_str().unwrap();
        assert!(set_cookie_header.contains("auth_token="));
        assert!(set_cookie_header.contains("Max-Age=0"));
        assert!(set_cookie_header.contains("HttpOnly"));
        assert!(set_cookie_header.contains("Secure"));
        assert!(set_cookie_header.contains("SameSite=Lax"));

        // Check body
        let body_bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["message"], "Logged out");
    }
}
