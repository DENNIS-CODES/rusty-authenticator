#![allow(dead_code)]

use actix_web::{web, App, HttpResponse, HttpServer};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use dotenv::dotenv;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use prisma::{prisma_client_rust_cli, PrismaClient};
use regex::Regex;
use std::env;
use std::sync::Mutex;
use validator::validate_email;

// In-memory storage for simplicity
struct AppState {
    users: Mutex<Vec<User>>,
}

struct User {
    id: String,
    username: String,
    password_hash: String,
    email: String,
    phone_number: String,
    created_at: String,
    updated_at: String,
}

async fn register_user(
    data: web::Json<RegisterRequest>,
    state: web::Data<AppState>,
    db: post,
) -> HttpResponse {
    let mut users = state.users.lock().unwrap();

    // Check if the username is already taken
    if users.iter().any(|user| user.username == data.username) {
        return HttpResponse::Conflict().body("Username already taken");
    }

    // Validate phone number format
    let phone_number_regex = Regex::new(r"^(?:\+254|07|7)\d{8}$").unwrap();
    if !phone_number_regex.is_match(&data.phone_number) {
        return HttpResponse::BadRequest().body("Invalid phone number format");
    }

    // Validate email
    if !validate_email(&data.email) {
        return HttpResponse::BadRequest().body("Invalid email format");
    }

    // Validate password
    if data.password.len() < 8
        || !data.password.chars().any(char::is_uppercase)
        || !data.password.chars().any(char::is_lowercase)
        || !data.password.chars().any(char::is_numeric)
    {
        return HttpResponse::BadRequest().body("Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, and a digit");
    }

    // Hash the password
    let password_hash = match hash(&data.password, DEFAULT_COST) {
        Ok(hash) => hash,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    // Check if the password is the same as the confirm password
    if data.password != data.confirm_password {
        return HttpResponse::BadRequest().body("Password and confirm password do not match");
    }

    let now = Utc::now();
    // Create a new user
    let user = User {
        id: prisma_client_rust::PrismaValue().to_string(),
        username: data.username.clone(),
        password_hash,
        phone_number: data.phone_number.clone(),
        email: data.email.clone(),
        created_at: now.to_string(),
        updated_at: now.to_string(),
    };

    // Store the user in the state
    users.push(user.Clone());

    // Save the user in MongoDB
    let user_data = post::user::create(
        user.username,
        user.password_hash,
        user.email,
        user.phone_number,
    );
    db.run(user_data).await;

    HttpResponse::Ok().body("User registered successfully")
}

async fn login_user(
    data: web::Json<LoginRequest>,
    state: web::Data<AppState>,
    db: post,
) -> HttpResponse {
    let users = state.users.lock().unwrap();

    // Find the user by username
    let user = match users.iter().find(|user| {
        user.username == data.username
            || user.phone_number == data.username
            || user.email == data.username
    }) {
        Some(user) => user,
        None => return HttpResponse::NotFound().body("User not found"),
    };

    // Verify the password
    let password_match = match verify(&data.password, &user.password_hash) {
        Ok(matched) => matched,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    if password_match {
        let now = Utc::now();
        let payload = AuthPayload {
            sub: user.id.clone(),
            iat: now.timestamp(),
            exp: (now + Duration::hours(24)).timestamp(),
        };
        let encoding_key = EncodingKey::from_secret(env::var("JWT_SECRET").unwrap().as_bytes());
        let token = match encode(&Header::default(), &payload, &encoding_key) {
            Ok(token) => token,
            Err(_) => return HttpResponse::InternalServerError().finish(),
        };
        let user_data = prisma::user::login(user.username.clone(), data.password.clone());
        db.run(user_data).await;
        HttpResponse::Ok().json(LoginResponse {
            token,
            msg: "Login successful".to_owned(),
        })
    } else {
        HttpResponse::Unauthorized().body("Invalid password")
    }
}

#[derive(serde::Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
    email: String,
    confirm_password: String,
    phone_number: String,
    created_at: String,
    updated_at: String,
}

#[derive(serde::Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(serde::Serialize)]
struct LoginResponse {
    token: String,
    msg: String,
}

struct AuthPayload {
    sub: String,
    iat: i64,
    exp: i64,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let client = PrismaClient::_builder()
        .build()
        .await
        .expect("Failed to create Prisma client.");
    dotenv().ok();
    // Create the initial state
    let app_state = web::Data::new(AppState {
        users: Mutex::new(vec![]),
    });

    // Start the HTTP server
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
