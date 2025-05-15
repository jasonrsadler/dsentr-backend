use axum::{
    http::{
        header::SET_COOKIE, 
        HeaderMap, 
        HeaderValue, 
        StatusCode
    }, 
    response::IntoResponse
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

    
    (
        StatusCode::OK,
        headers,
        JsonResponse::success("Logged out")
    )
}