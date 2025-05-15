use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation, Algorithm, TokenData, errors::Error};
use std::env;
use crate::routes::auth::claims::Claims;

fn jwt_secret() -> String {
    env::var("JWT_SECRET").expect("JWT_SECRET must be set")
}

pub fn create_jwt(claims: &Claims) -> Result<String, Error> {
    let key = EncodingKey::from_secret(jwt_secret().as_bytes());
    encode(&Header::default(), claims, &key)
}

pub fn decode_jwt(token: &str) -> Result<TokenData<Claims>, Error> {
    let key = DecodingKey::from_secret(jwt_secret().as_bytes());
    decode::<Claims>(
        token,
        &key,
        &Validation::new(Algorithm::HS256),
    )
}