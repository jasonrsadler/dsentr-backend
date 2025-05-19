use std::collections::HashMap;

use axum::{extract::Query, response::{IntoResponse, Redirect}};
use http::StatusCode;

pub async fn google_login() -> impl IntoResponse {
    let client_id = std::env::var("GOOGLE_CLIENT_ID").unwrap();
    let redirect_uri = std::env::var("GOOGLE_REDIRECT_URI").unwrap();
    let state = generate_csrf_state(); // Store this in session or cookie
    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=email%20profile&state={}",
        client_id, redirect_uri, state
    );
    Redirect::to(&auth_url)
}

pub async fn google_callback(Query(params): Query<HashMap<String, String>>) -> Result<impl IntoResponse, StatusCode> {
    let code = params.get("code").ok_or(StatusCode::BAD_REQUEST)?;
    let state = params.get("state").ok_or(StatusCode::BAD_REQUEST)?;
    validate_csrf_state(state)?; // Validate state

    // Exchange code for tokens
    let client = reqwest::Client::new();
    let token_res = client.post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", code),
            ("client_id", &std::env::var("GOOGLE_CLIENT_ID")?),
            ("client_secret", &std::env::var("GOOGLE_CLIENT_SECRET")?),
            ("redirect_uri", &std::env::var("GOOGLE_REDIRECT_URI")?),
            ("grant_type", &"authorization_code".to_string()),
        ])
        .send().await?
        .json::<serde_json::Value>().await?;

    let access_token = token_res["access_token"].as_str().unwrap();

    // Fetch user info
    let user_info = client.get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(access_token)
        .send().await?
        .json::<serde_json::Value>().await?;

    let email = user_info["email"].as_str().unwrap();

    // Now: Check DB for user, create if needed, log in, set cookie etc.
    // (same flow as email/password login)

    Ok(Redirect::to("/dashboard"))
}
