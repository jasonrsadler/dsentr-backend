use serde::{Deserialize, Serialize};

use crate::models::user::UserRole;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Claims {
    pub id: String, // user ID or UUID
    pub email: String,
    pub exp: usize, // expiration (as UNIX timestamp)
    pub first_name: String,
    pub last_name: String,
    // Optional fields
    pub role: Option<UserRole>,
    pub plan: Option<String>,
    pub company_name: Option<String>,
}
