use axum::{
    extract::{Query, State}, response::{IntoResponse, Redirect, Response},
    http::header
};
use axum_extra::extract::{cookie::{Cookie, SameSite}, CookieJar};
use serde::{Deserialize, Serialize};
use reqwest::Client;
use serde_json::Value;
use sqlx::query_as;

use crate::{models::user::User, responses::JsonResponse, state::AppState, utils::jwt::create_jwt};
use crate::utils::csrf::generate_csrf_token;

use super::{claims::Claims, signup::OauthProvider};

pub async fn github_login() -> impl IntoResponse {
    let client_id = std::env::var("GITHUB_CLIENT_ID").expect("Missing GITHUB_CLIENT_ID");
    let redirect_uri = std::env::var("GITHUB_REDIRECT_URI").expect("Missing GITHUB_REDIRECT_URI");
    let scope = std::env::var("GITHUB_OAUTH_SCOPE").unwrap_or_else(|_| "user:email".to_string());

    let state_token = generate_csrf_token();

    let github_auth_url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope={}&state={}",
        client_id, redirect_uri, scope, state_token
    );

    let oauth_state_cookie = Cookie::build(("oauth_state", state_token))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(time::Duration::minutes(10))
        .build();

    (
        [(header::SET_COOKIE, oauth_state_cookie.to_string())],
        Redirect::to(&github_auth_url),
    )
}

#[derive(Deserialize)]
pub struct GitHubCallback {
    code: String,
    state: String,
}

#[derive(Deserialize)]
struct GitHubAccessTokenResponse {
    access_token: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
    visibility: Option<String>,
}

pub async fn github_callback(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(params): Query<GitHubCallback>,
) -> Response {
    // 1. Validate CSRF state cookie
    let expected_state = match jar.get("oauth_state").map(|c| c.value().to_string()) {
        Some(state) => state,
        None => return JsonResponse::redirect_to_login_with_error("Missing 'oauth_state' cookie").into_response(),
    };

    if params.state != expected_state {
        return JsonResponse::redirect_to_login_with_error("Invalid state").into_response();
    }

    let client_id = std::env::var("GITHUB_CLIENT_ID").unwrap();
    let client_secret = std::env::var("GITHUB_CLIENT_SECRET").unwrap();

    // 2. Exchange code for access token
    let token_response = Client::new()
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .form(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("code", &params.code),
            ("state", &params.state),
        ])
        .send()
        .await;

    let token_json: GitHubAccessTokenResponse = match token_response {
        Ok(resp) => match resp.json().await {
            Ok(json) => json,
            Err(_) => return JsonResponse::redirect_to_login_with_error("Invalid GitHub token").into_response(),
        },
        Err(_) => return JsonResponse::redirect_to_login_with_error("GitHub token request failed").into_response(),
    };

    // 3b. Fetch GitHub user profile info (name, login, etc.)
    let user_info_res = Client::new()
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {}", token_json.access_token))
        .header("User-Agent", "dsentr-app")
        .send()
        .await;

    let user_info: Value = match user_info_res {
        Ok(resp) => match resp.json().await {
            Ok(json) => json,
            Err(_) => return JsonResponse::redirect_to_login_with_error("Failed to decode GitHub user info").into_response(),
        },
        Err(_) => return JsonResponse::redirect_to_login_with_error("GitHub user info request failed").into_response(),
    };

    // 3. Get user's primary verified email
    let emails_response = Client::new()
        .get("https://api.github.com/user/emails")
        .header("Authorization", format!("Bearer {}", token_json.access_token))
        .header("User-Agent", "dsentr-app") // GitHub requires this
        .send()
        .await;

    let emails: Vec<GitHubEmail> = match emails_response {
        Ok(resp) => match resp.json().await {
            Ok(json) => json,
            Err(_) => return JsonResponse::redirect_to_login_with_error("Failed to decode GitHub email").into_response(),
        },
        Err(_) => return JsonResponse::redirect_to_login_with_error("GitHub email request failed").into_response(),
    };

    let email = match emails.into_iter().find(|e| e.primary && e.verified) {
        Some(e) => e.email,
        None => return JsonResponse::redirect_to_login_with_error("No verified GitHub email found").into_response(),
    };

    let full_name = user_info["name"].as_str().unwrap_or("").to_string();
    let login = user_info["login"].as_str().unwrap_or("").to_string();

    // Try to split full name into first and last, fallback to login
    let (first_name, last_name) = if !full_name.is_empty() {
        let parts: Vec<&str> = full_name.split_whitespace().collect();
        let first = parts.get(0).unwrap_or(&"").to_string();
        let last = parts.get(1..).map(|s| s.join(" ")).unwrap_or_default();
        (first, last)
    } else {
        (login.clone(), "".to_string())
    };

    // 4. Lookup or create user
    let user = match query_as::<_, User>(
    r#"SELECT id, email, role, password_hash, first_name, last_name, plan, company_name, oauth_provider FROM users WHERE email = $1"#
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(user)) => {
            match (&user.oauth_provider, OauthProvider::Github) {
                // ✅ user signed up with Github, allow login
                (Some(OauthProvider::Github), _) => user,

                // ❌ user signed up with email/password
                (None, _) => {
                    return JsonResponse::redirect_to_login_with_error("This account was created using email/password. Please log in with email.").into_response();
                }

                // ❌ user signed up with another OAuth provider (e.g., GitHub)
                (Some(other), _) => {
                    let reveal_provider = true;

                    if reveal_provider {
                        return JsonResponse::redirect_to_login_with_error(&format!(
                            "This account is linked to {:?}. Please use that provider to log in.",
                            other
                        ))
                        .into_response();
                    } else {
                        return JsonResponse::redirect_to_login_with_error("Unable to log in with this method. Please use the method you originally signed up with.").into_response();
                    }
                }
            }
        }

        Ok(None) => {
            // First-time login, create user with Github as oauth_provider
            match query_as::<_, User>(
                r#"
                INSERT INTO users (email, password_hash, first_name, last_name, oauth_provider, is_verified, role)
                VALUES ($1, $2, $3, $4, $5, true, 'user')
                RETURNING id, role, email, password_hash, first_name, last_name, plan, company_name, oauth_provider
                "#
            )
            .bind(&email)
            .bind("") // password_hash
            .bind(&first_name)
            .bind(&last_name)
            .bind(OauthProvider::Github)
            .fetch_one(&state.db)
            .await
            {
                Ok(new_user) => new_user,
                Err(e) => {
                    eprintln!("DB create error: {:?}", e);
                    return JsonResponse::redirect_to_login_with_error("User creation failed").into_response()
                }
            }
        }

        Err(e) => {
            eprintln!("DB query error: {:?}", e);
            return JsonResponse::redirect_to_login_with_error("DB query failed").into_response();
        }
    };

    // 5. Generate JWT
    let claims = Claims {
        id: user.id.to_string(),
        role: user.role,
        exp: (chrono::Utc::now() + chrono::Duration::days(30)).timestamp() as usize,
        email: user.email.clone(),
        first_name: user.first_name,
        last_name: user.last_name,
        plan: None,
        company_name: None,
    };

    let jwt = match create_jwt(&claims) {
        Ok(token) => token,
        Err(_) => return JsonResponse::redirect_to_login_with_error("JWT generation failed").into_response(),
    };

    let auth_cookie = Cookie::build(("auth_token", jwt))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(time::Duration::days(30))
        .build();

    let clear_state_cookie = Cookie::build(("oauth_state", ""))
        .path("/")
        .max_age(time::Duration::seconds(0))
        .build();

    let frontend_url = std::env::var("FRONTEND_ORIGIN").unwrap_or_else(|_| "https://localhost:5173".to_string());

    let jar = CookieJar::new()
        .add(auth_cookie)
        .add(clear_state_cookie);

    (jar, Redirect::to(&format!("{}/dashboard", frontend_url))).into_response()
}
