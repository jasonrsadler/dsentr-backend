use std::collections::HashMap;

use axum::{extract::{Query, State}, http::header, response::{IntoResponse, Redirect, Response}};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use reqwest::Url;
use serde_json::Value;

use crate::{models::user::OauthProvider, responses::JsonResponse, utils::csrf::generate_csrf_token};
use crate::AppState;
use crate::routes::auth::claims::Claims;
use crate::utils::jwt::create_jwt;

pub async fn google_login() -> impl IntoResponse {
    let client_id = std::env::var("GOOGLE_CLIENT_ID").unwrap();
    let redirect_uri = std::env::var("GOOGLE_REDIRECT_URI").unwrap();
    let mut url = Url::parse(&std::env::var("GOOGLE_ACCOUNTS_OAUTH_API_BASE").unwrap()).unwrap();

    let state = generate_csrf_token();

    url.query_pairs_mut()
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", "email profile")
        .append_pair("state", &state);

    let oauth_state_cookie = Cookie::build(("oauth_state", state))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(time::Duration::minutes(10))
        .build();

    (
        [(header::SET_COOKIE, oauth_state_cookie.to_string())],
        Redirect::to(url.as_str()),
    )

}

pub async fn google_callback(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let code = match params.get("code") {
        Some(code) => code,
        None => return JsonResponse::redirect_to_login_with_error("Missing 'code' param").into_response()
    };

    let state_param = match params.get("state") {
        Some(state) => state,
        None => return JsonResponse::redirect_to_login_with_error("Missing 'state' param").into_response(),
    };

    let expected_state = match jar.get("oauth_state").map(|c| c.value().to_string()) {
        Some(state) => state,
        None => return JsonResponse::redirect_to_login_with_error("Missing 'oauth_state' cookie").into_response(),
    };

    if state_param != &expected_state {
        return JsonResponse::redirect_to_login_with_error("Invalid state").into_response();
    }

    let client = reqwest::Client::new();

    let token_res = client
        .post(std::env::var("GOOGLE_ACCOUNTS_OAUTH_TOKEN_CLIENT_URL").unwrap())
        .form(&[
            ("code", code),
            ("client_id", &std::env::var("GOOGLE_CLIENT_ID").unwrap()),
            ("client_secret", &std::env::var("GOOGLE_CLIENT_SECRET").unwrap()),
            ("redirect_uri", &std::env::var("GOOGLE_REDIRECT_URI").unwrap()),
            ("grant_type", &"authorization_code".to_string()),
        ])
        .send()
        .await;

    let token_res = match token_res {
        Ok(resp) if resp.status().is_success() => resp,
        Ok(err_resp) => {
            let text = err_resp.text().await.unwrap_or_default();
            return JsonResponse::redirect_to_login_with_error(&format!("Token request failed: {}", text)).into_response();
        },
        Err(_) => return JsonResponse::redirect_to_login_with_error("Token request failed").into_response(),
    };

    let token_json: Value = match token_res.json().await {
        Ok(json) => json,
        Err(_) => return JsonResponse::redirect_to_login_with_error("Invalid token response").into_response(),
    };

    let access_token = match token_json["access_token"].as_str() {
        Some(token) => token,
        None => return JsonResponse::redirect_to_login_with_error("Missing access_token").into_response(),
    };

    let user_info_res = client
        .get(std::env::var("GOOGLE_ACCOUNTS_OAUTH_USER_INFO_URL").unwrap())
        .bearer_auth(access_token)
        .send()
        .await;

    let user_info_res = match user_info_res {
        Ok(resp) if resp.status().is_success() => resp,
        _ => return JsonResponse::redirect_to_login_with_error("Failed to fetch user info").into_response(),
    };

    let user_info: Value = match user_info_res.json().await {
        Ok(info) => info,
        Err(_) => return JsonResponse::redirect_to_login_with_error("Invalid user info response").into_response(),
    };

    let email = match user_info["email"].as_str() {
        Some(email) => email,
        None => return JsonResponse::redirect_to_login_with_error("Missing email in user info").into_response(),
    };
                    
    let first_name = user_info["given_name"].as_str().unwrap_or("").to_string();
    let last_name = user_info["family_name"].as_str().unwrap_or("").to_string();

    let user = match state.db.find_user_by_email(&email).await {
    Ok(Some(user)) => {
        match (&user.oauth_provider, OauthProvider::Google) {
            // ✅ user signed up with Google, allow login
            (Some(OauthProvider::Google), _) => user,

            // ❌ user signed up with email/password
            (None, _) => {
                return JsonResponse::redirect_to_login_with_error(
                    "This account was created using email/password. Please log in with email."
                ).into_response();
            }

            // ❌ user signed up with another OAuth provider (e.g., GitHub)
            (Some(other), _) => {
                let reveal_provider = true;

                if reveal_provider {
                    return JsonResponse::redirect_to_login_with_error(&format!(
                        "This account is linked to {:?}. Please use that provider to log in.",
                        other
                    )).into_response();
                } else {
                    return JsonResponse::redirect_to_login_with_error(
                        "Unable to log in with this method. Please use the method you originally signed up with."
                    ).into_response();
                }
            }
        }
    }

    Ok(None) => {
        // First-time login, create user with Google as oauth_provider
        match state.db.create_user_with_oauth(
            &email,
            &first_name,
            &last_name,
            OauthProvider::Google,
        ).await {
            Ok(new_user) => new_user,
            Err(e) => {
                eprintln!("DB create error: {:?}", e);
                return JsonResponse::redirect_to_login_with_error("User creation failed").into_response();
            }
        }
    }

    Err(e) => {
        eprintln!("DB query error: {:?}", e);
        return JsonResponse::redirect_to_login_with_error("DB query failed").into_response();
    }
};
    let claims = Claims {
        id: user.id.to_string(),
        role: user.role,
        exp: (chrono::Utc::now() + chrono::Duration::days(30)).timestamp() as usize,
        email: email.to_string(),
        first_name,
        last_name,
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
    let frontend_url = std::env::var("FRONTEND_ORIGIN").unwrap_or_else(|_| "https://localhost:5173".to_string());


    let clear_state_cookie = Cookie::build(("oauth_state", ""))
        .path("/")
        .max_age(time::Duration::seconds(0))
        .build();

    let jar = CookieJar::new()
        .add(auth_cookie)
        .add(clear_state_cookie);
    (jar, Redirect::to(&format!("{}/dashboard", frontend_url))).into_response()
}
