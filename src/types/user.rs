use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub confirm_password: String,
    pub email: String,
    pub phone_number: String,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub msg: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthPayload {
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
}