use axum::{
    body::Body, 
    http::{
        Method, 
        Request, 
        StatusCode,
        header::SET_COOKIE,
        HeaderMap,
        HeaderValue
    }, 
    middleware::Next, 
    response::{Response, IntoResponse}
};
use axum_extra::extract::cookie::Cookie;
use base64::{
    self, 
    prelude::BASE64_URL_SAFE_NO_PAD, 
    Engine
};
use rand_core::RngCore;

pub struct CsrfLayer;

impl Default for CsrfLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl CsrfLayer {
    pub fn new() -> Self {
        Self
    }
}

pub async fn validate_csrf(req: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    if matches!(
        req.method(),
        &Method::POST | &Method::PUT | &Method::DELETE | &Method::PATCH
    ) {
        let headers = req.headers();

        let token_header = headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok());

        let cookie_header = req
            .headers()
            .get_all("cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect::<Vec<_>>()
            .join("; ");
        
        if let Some(csrf_token) = token_header {
            if let Some(cookie_token) = extract_csrf_from_cookie(&cookie_header) {
                if csrf_token == cookie_token {
                    return Ok(next.run(req).await);
                }
            }
        }
        Err(StatusCode::FORBIDDEN)
    } else {
        Ok(next.run(req).await)
    }
}

fn extract_csrf_from_cookie(cookie_str: &str) -> Option<String> {
    for cookie in cookie_str.split(';') {
        if let Ok(parsed) = Cookie::parse_encoded(cookie.trim()) {
            if parsed.name() == "csrf_token" {
                return Some(parsed.value().to_string());
            }
        }
    }
    None
}

pub fn generate_csrf_token() -> String {
    let mut bytes = [0u8; 32]; // 256-bit token
    rand_core::OsRng.fill_bytes(&mut bytes);
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

pub async fn get_csrf_token() -> Response {
    let token = generate_csrf_token();

    let set_cookie_value = format!(
        "csrf_token={}; Path=/; SameSite=Strict; HttpOnly; Secure",
        token
    );

    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, HeaderValue::from_str(&set_cookie_value).unwrap());

    // Return the token in the body in case the frontend needs it, with headers
    (StatusCode::OK, headers, token).into_response()
}
