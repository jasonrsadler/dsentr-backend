use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};
use axum_extra::extract::cookie::CookieJar;

use crate::utils::jwt::decode_jwt;
use crate::routes::auth::claims::Claims;

pub struct AuthSession(pub Claims);

impl<S> FromRequestParts<S> for AuthSession
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let token = jar.get("auth_token").ok_or(StatusCode::UNAUTHORIZED)?;

        let claims = decode_jwt(token.value()).map_err(|_| StatusCode::UNAUTHORIZED)?;

        Ok(AuthSession(claims.claims))
    }
}