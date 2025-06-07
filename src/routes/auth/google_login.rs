use std::collections::HashMap;

use axum::{
    extract::{Query, State},
    http::header,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use reqwest::Url;

use crate::utils::jwt::create_jwt;
use crate::AppState;
use crate::{
    models::user::OauthProvider, responses::JsonResponse, utils::csrf::generate_csrf_token,
};
use crate::{routes::auth::claims::Claims, services::oauth::google::errors::GoogleAuthError};

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
        None => {
            return JsonResponse::redirect_to_login_with_error("Missing 'code' param")
                .into_response()
        }
    };

    let state_param = match params.get("state") {
        Some(state) => state,
        None => {
            return JsonResponse::redirect_to_login_with_error("Missing 'state' param")
                .into_response()
        }
    };

    let expected_state = match jar.get("oauth_state").map(|c| c.value().to_string()) {
        Some(state) => state,
        None => {
            return JsonResponse::redirect_to_login_with_error(
                &GoogleAuthError::MissingStateCookie.to_string(),
            )
            .into_response()
        }
    };

    if state_param != &expected_state {
        return JsonResponse::redirect_to_login_with_error(
            &GoogleAuthError::InvalidState.to_string(),
        )
        .into_response();
    }

    let access_token = match state.google_oauth.exchange_code_for_token(code).await {
        Ok(token) => token,
        Err(e) => {
            eprintln!("Token error: {:?}", e);
            return JsonResponse::redirect_to_login_with_error(
                &GoogleAuthError::TokenExchangeFailed.to_string(),
            )
            .into_response();
        }
    };

    let user_info = match state.google_oauth.fetch_user_info(&access_token).await {
        Ok(info) => info,
        Err(e) => {
            eprintln!("User info error: {:?}", e);
            return JsonResponse::redirect_to_login_with_error(
                &GoogleAuthError::UserInfoFetchFailed.to_string(),
            )
            .into_response();
        }
    };

    let email = match user_info["email"].as_str() {
        Some(email) => email,
        None => {
            return JsonResponse::redirect_to_login_with_error(
                &GoogleAuthError::NoEmailFound.to_string(),
            )
            .into_response()
        }
    };

    let first_name = user_info["given_name"].as_str().unwrap_or("").to_string();
    let last_name = user_info["family_name"].as_str().unwrap_or("").to_string();

    let user = match state.db.find_user_by_email(email).await {
        Ok(Some(user)) => {
            match (&user.oauth_provider, OauthProvider::Google) {
                // ✅ user signed up with Google, allow login
                (Some(OauthProvider::Google), _) => user,

                // ❌ user signed up with email/password
                (None, _) => {
                    return JsonResponse::redirect_to_login_with_error(
                        "This account was created using email/password. Please log in with email.",
                    )
                    .into_response();
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
                        return JsonResponse::redirect_to_login_with_error(
                        "Unable to log in with this method. Please use the method you originally signed up with."
                    ).into_response();
                    }
                }
            }
        }

        Ok(None) => {
            // First-time login, create user with Google as oauth_provider
            match state
                .db
                .create_user_with_oauth(email, &first_name, &last_name, OauthProvider::Google)
                .await
            {
                Ok(new_user) => new_user,
                Err(e) => {
                    eprintln!("DB create error: {:?}", e);
                    return JsonResponse::redirect_to_login_with_error(
                        &GoogleAuthError::UserCreationFailed.to_string(),
                    )
                    .into_response();
                }
            }
        }

        Err(e) => {
            eprintln!("DB query error: {:?}", e);
            return JsonResponse::redirect_to_login_with_error(
                &GoogleAuthError::DbError(e).to_string(),
            )
            .into_response();
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
        Err(_) => {
            return JsonResponse::redirect_to_login_with_error(
                &GoogleAuthError::JwtCreationFailed.to_string(),
            )
            .into_response()
        }
    };

    let auth_cookie = Cookie::build(("auth_token", jwt))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(time::Duration::days(30))
        .build();
    let frontend_url =
        std::env::var("FRONTEND_ORIGIN").unwrap_or_else(|_| "https://localhost:5173".to_string());

    let clear_state_cookie = Cookie::build(("oauth_state", ""))
        .path("/")
        .max_age(time::Duration::seconds(0))
        .build();

    let jar = CookieJar::new().add(auth_cookie).add(clear_state_cookie);
    (jar, Redirect::to(&format!("{}/dashboard", frontend_url))).into_response()
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        response::IntoResponse,
        routing::get,
        Router,
    };
    use axum_extra::extract::cookie::CookieJar;
    use serde_json::Value;
    use std::{collections::HashMap, sync::Arc};
    use tower::ServiceExt;

    use crate::{
        db::mock_db::MockDb,
        routes::auth::google_login::{google_callback, google_login},
        services::{
            oauth::{
                github::mock_github_oauth::MockGitHubOAuth,
                google::{
                    errors::GoogleAuthError, mock_google_oauth::MockGoogleOAuth,
                    service::GoogleOAuthService,
                },
            },
            smtp_mailer::MockMailer,
        },
        state::AppState,
    }; // for `.oneshot()`

    #[tokio::test]
    async fn test_google_login_sets_cookie_and_redirects() {
        std::env::set_var("GOOGLE_CLIENT_ID", "test_client_id");
        std::env::set_var("GOOGLE_REDIRECT_URI", "test_client_secret");
        std::env::set_var(
            "GOOGLE_ACCOUNTS_OAUTH_API_BASE",
            "https://accounts.google.com/o/oauth2/auth",
        );
        let app = Router::new().route("/auth/google", get(google_login));

        let response = app
            .oneshot(Request::get("/auth/google").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert!(matches!(
            response.status(),
            StatusCode::FOUND | StatusCode::SEE_OTHER
        ));

        let headers = response.headers();
        let location = headers.get("location").unwrap().to_str().unwrap();
        assert!(location.contains("https://accounts.google.com/o/oauth2/auth?client_id=test_client_id&redirect_uri=test_client_secret&response_type=code&scope=email+profile&state="));

        let set_cookie = headers.get("set-cookie").unwrap().to_str().unwrap();
        assert!(set_cookie.contains("oauth_state="));
    }

    #[tokio::test]
    async fn test_google_callback_missing_state_cookie() {
        let repo = Arc::new(MockDb::default());
        let mailer = Arc::new(MockMailer::default());
        let google_oauth = Arc::new(MockGoogleOAuth::default());
        let github_oauth = Arc::new(MockGitHubOAuth::default());
        let app_state = AppState {
            db: repo,
            mailer,
            google_oauth,
            github_oauth,
        };

        let code = "dummy";
        let state = "invalid";

        let jar = CookieJar::new(); // no cookies = missing oauth_state

        let response = google_callback(
            axum::extract::State(app_state),
            jar,
            axum::extract::Query({
                HashMap::from([
                    ("code".to_string(), code.to_string()),
                    ("state".to_string(), state.to_string()),
                ])
            }),
        )
        .await
        .into_response();

        // Should redirect to /login with an error
        assert!(
            matches!(response.status(), StatusCode::FOUND | StatusCode::SEE_OTHER),
            "Expected 302 or 303, got {}",
            response.status()
        );

        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();

        assert!(location.contains("/login?error="));
        let binding = GoogleAuthError::MissingStateCookie.to_string();
        let expected = urlencoding::encode(&binding);
        assert!(location.contains(&expected.to_string()));
    }

    #[tokio::test]
    async fn test_google_callback_internal_failure() {
        std::env::set_var("GOOGLE_CLIENT_ID", "test_client_id");
        std::env::set_var("GOOGLE_CLIENT_SECRET", "test_client_secret");

        // Mock that simulates failure — override GitHubOAuth behavior
        #[derive(Default)]
        struct FailingGoogleOAuth;

        #[async_trait]
        impl GoogleOAuthService for FailingGoogleOAuth {
            async fn exchange_code_for_token(
                &self,
                _code: &str,
            ) -> Result<String, GoogleAuthError> {
                Err(GoogleAuthError::TokenExchangeFailed)
            }

            async fn fetch_user_info(&self, _token: &str) -> Result<Value, GoogleAuthError> {
                unreachable!()
            }
        }

        let app_state = AppState {
            db: Arc::new(MockDb::default()),
            mailer: Arc::new(MockMailer::default()),
            google_oauth: Arc::new(FailingGoogleOAuth),
            github_oauth: Arc::new(MockGitHubOAuth::default()),
        };

        let code = "dummy";
        let state = "dummy";
        let jar = CookieJar::new().add(axum_extra::extract::cookie::Cookie::new(
            "oauth_state",
            "dummy",
        ));

        let response = google_callback(
            axum::extract::State(app_state),
            jar,
            axum::extract::Query({
                HashMap::from([
                    ("code".to_string(), code.to_string()),
                    ("state".to_string(), state.to_string()),
                ])
            }),
        )
        .await
        .into_response();

        // Expect redirect to /login?error=GitHub+login+failed
        assert!(
            matches!(response.status(), StatusCode::FOUND | StatusCode::SEE_OTHER),
            "Expected 302 or 303, got {}",
            response.status()
        );

        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.contains("/login?error="));
        let binding = GoogleAuthError::TokenExchangeFailed.to_string();
        let expected = urlencoding::encode(&binding);
        assert!(location.contains(&expected.to_string()));
    }
}
