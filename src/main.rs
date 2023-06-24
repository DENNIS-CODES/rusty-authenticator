use actix_web::{web, App, HttpResponse, HttpServer};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use dotenv::dotenv;
use jsonwebtoken::{encode, EncodingKey, Header};
use prisma_client_rust::PrismaClient;
use regex::Regex;
extern crate serde;
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Mutex;
use validator::validate_email;
use uuid::Uuid;

struct AppState {
    users: Mutex<Vec<User>>,
}

#[derive(Clone)]
struct User {
    id: String,
    username: String,
    password_hash: String,
    email: String,
    phone_number: String,
    created_at: String,
    updated_at: String,
}

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
    email: String,
    confirm_password: String,
    phone_number: String,
    created_at: String,
    updated_at: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    msg: String,
}

#[derive(Serialize)]
struct AuthPayload {
    sub: String,
    iat: i64,
    exp: i64,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let client = PrismaClient::new()
        .await
        .expect("Failed to create Prisma client.");

    let app_state = web::Data::new(AppState {
        users: Mutex::new(vec![]),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .service(web::resource("/register").route(web::post().to(register_user)))
            .service(web::resource("/login").route(web::post().to(login_user)))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

async fn register_user(
    data: web::Json<RegisterRequest>,
    state: web::Data<AppState>,
    db: web::Data<dyn PrismaClient>,
) -> HttpResponse {
    let mut users = state.users.lock().unwrap();

    let existing_user = db
        .user()
        .find_unique(prisma_client_rust::user::username::equals(
            data.username.clone(),
        ))
        .exec()
        .await
        .unwrap();

    if existing_user.is_err() {
        return HttpResponse::Conflict().body("Username already taken");
    }

    let phone_number_regex = Regex::new(r"^(?:\+254|07|7)\d{8}$").unwrap();
    if !phone_number_regex.is_match(&data.phone_number) {
        return HttpResponse::BadRequest().body("Invalid phone number format");
    }

    if !validate_email(&data.email) {
        return HttpResponse::BadRequest().body("Invalid email format");
    }

    if data.password.len() < 8
        || !data.password.chars().any(char::is_uppercase)
        || !data.password.chars().any(char::is_lowercase)
        || !data.password.chars().any(char::is_numeric)
    {
        return HttpResponse::BadRequest().body("Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, and a digit");
    }

    let password_hash = match hash(&data.password, DEFAULT_COST) {
        Ok(hash) => hash,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    if data.password != data.confirm_password {
        return HttpResponse::BadRequest().body("Passwords do not match");
    }

    let user = User {
        id: uuid::Uuid::new_v4().to_string(),
        username: data.username.clone(),
        password_hash,
        email: data.email.clone(),
        phone_number: data.phone_number.clone(),
        created_at: data.created_at.clone(),
        updated_at: data.updated_at.clone(),
    };

    users.push(user.clone());

    HttpResponse::Ok().body("User registered successfully")
}

async fn login_user(
    data: web::Json<LoginRequest>,
    state: web::Data<AppState>,
    db: web::Data<dyn PrismaClient>,
) -> HttpResponse {
    let users = state.users.lock().unwrap();

    let user = db
        .user()
        .find_unique(prisma_client_rust::user::username::equals(
            data.username.clone(),
        ))
        .exec()
        .await
        .unwrap();

    if let Ok(user) = user {
        if let Ok(matches) = verify(&data.password, &user.password_hash) {
            if matches {
                let header = Header::default();
                let my_claims = AuthPayload {
                    sub: user.id.to_owned(),
                    iat: Utc::now().timestamp(),
                    exp: (Utc::now() + Duration::hours(24)).timestamp(),
                };
                let key = EncodingKey::from_secret(env::var("JWT_SECRET").unwrap().as_bytes());
                if let Ok(token) = encode(&header, &my_claims, &key) {
                    return HttpResponse::Ok().json(LoginResponse {
                        token,
                        msg: "Login successful".to_owned(),
                    });
                }
            }
        }
    }

    HttpResponse::Unauthorized().body("Username or password is incorrect")
}
