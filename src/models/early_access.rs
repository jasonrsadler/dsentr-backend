use serde::Deserialize;

#[derive(Deserialize)]
pub struct EarlyAccessPayload {
    pub email: String,
}
