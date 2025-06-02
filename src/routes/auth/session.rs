use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};
use axum_extra::extract::cookie::CookieJar;

use crate::routes::auth::claims::Claims;
use crate::utils::jwt::decode_jwt;

#[derive(Debug, PartialEq)]
pub struct AuthSession(pub Claims);

impl<S> FromRequestParts<S> for AuthSession
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let token = jar.get("auth_token").ok_or(StatusCode::UNAUTHORIZED)?;

        let claims = decode_jwt(token.value()).map_err(|_| StatusCode::UNAUTHORIZED)?;

        Ok(AuthSession(claims.claims))
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        extract::FromRequestParts,
        http::{header, HeaderMap, Method, Request, StatusCode},
    };
    use axum_extra::extract::cookie::Cookie;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{models::user::UserRole, routes::auth::claims::Claims};
    use crate::{routes::auth::session::AuthSession, utils::jwt::create_jwt};

    fn make_valid_jwt() -> String {
        let claims = Claims {
            id: "user_id_123".into(),
            email: "test@example.com".into(),
            first_name: "Test".into(),
            last_name: "User".into(),
            role: Some(UserRole::User),
            plan: Some("free".into()),
            company_name: Some("Acme Inc".into()),
            exp: (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600) as usize,
        };
        create_jwt(&claims).expect("JWT should create successfully")
    }

    #[tokio::test]
    async fn test_valid_token_extracted() {
        let jwt = make_valid_jwt();
        let cookie = Cookie::new("auth_token", jwt);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            header::HeaderValue::from_str(&cookie.to_string()).unwrap(),
        );

        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(header::COOKIE, cookie.to_string())
            .body(())
            .unwrap();

        let mut parts = request.into_parts().0;
        let result = AuthSession::from_request_parts(&mut parts, &()).await;

        assert!(result.is_ok());
        let session = result.unwrap();
        assert_eq!(session.0.email, "test@example.com");
        assert_eq!(session.0.role, Some(UserRole::User));
    }

    #[tokio::test]
    async fn test_missing_cookie_returns_unauthorized() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(())
            .unwrap();

        let mut parts = request.into_parts().0;
        let result = AuthSession::from_request_parts(&mut parts, &()).await;

        assert_eq!(result, Err(StatusCode::UNAUTHORIZED));
    }

    #[tokio::test]
    async fn test_invalid_token_returns_unauthorized() {
        let cookie = Cookie::new("auth_token", "invalid.token.here");

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            header::HeaderValue::from_str(&cookie.to_string()).unwrap(),
        );

        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(header::COOKIE, cookie.to_string())
            .body(())
            .unwrap();

        let mut parts = request.into_parts().0;
        let result = AuthSession::from_request_parts(&mut parts, &()).await;

        assert_eq!(result, Err(StatusCode::UNAUTHORIZED));
    }
}
