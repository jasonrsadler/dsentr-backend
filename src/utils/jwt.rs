use jsonwebtoken::{encode, Header, EncodingKey, errors::Result as JwtResult};
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub exp: i64,
}

pub fn create_jwt(claims: &Claims) -> JwtResult<String> {
    let key = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    encode(&Header::default(), claims, &EncodingKey::from_secret(key.as_bytes()))
}
