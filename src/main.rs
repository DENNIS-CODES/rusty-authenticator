#![allow(dead_code)]
use actix_web::{web, App, HttpResponse, HttpServer};
use bcrypt::{hash, verify, DEFAULT_COST};
use regex::Regex;
use std::sync::Mutex;
// In-memory storage for simplicity
struct AppState {
    users: Mutex<Vec<User>>,
}
struct User {
    username: String,
    password_hash: String,
    phone_number: String,
}

async fn register_user(
    data: web::Json<RegisterRequest>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let mut users = state.users.lock().unwrap();

    // Check if the username is already taken
    if users.iter().any(|user| user.username == data.username) {
        return HttpResponse::Conflict().body("Username already taken");
    }

    //validate phone number formart
    let phone_number_regex = Regex::new(r"^(?:\+254|07|7)\d{8}$").unwrap();
    if !phone_number_regex.is_match(&data.phone_number) {
        return HttpResponse::BadRequest().body("Invalid phone number format");
    }
    // validate password
    if data.password.len() < 8
        || !data.password.chars().any(char::is_uppercase)
        || !data.password.chars().any(char::is_lowercase)
        || !data.password.chars().any(char::is_numeric)
    {
        return HttpResponse::BadRequest().body("password must be at least 8 characters long , contain at least one uppercase lowercase letter and a digit");
    }
    // Hash the password
    let password_hash = match hash(&data.password, DEFAULT_COST) {
        Ok(hash) => hash,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    // check if the password is the same as the confirm password

    if data.password != data.confirm_password {
        return HttpResponse::BadRequest().body("password and confirm password do not match");
    }

    // Create a new user
    let user = User {
        username: data.username.clone(),
        password_hash,
        phone_number: data.phone_number.clone(),
    };

    // Store the user in the state
    users.push(user);

    HttpResponse::Ok().body("User registered successfully")
}

async fn login_user(data: web::Json<LoginRequest>, state: web::Data<AppState>) -> HttpResponse {
    let users = state.users.lock().unwrap();

    // Find the user by username
    let user = match users
        .iter()
        .find(|user| user.username == data.username || user.phone_number == data.username)
    {
        Some(user) => user,
        None => return HttpResponse::NotFound().body("User not found"),
    };

    // Verify the password
    let password_match = match verify(&data.password, &user.password_hash) {
        Ok(matched) => matched,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    if password_match {
        HttpResponse::Ok().body("Login successful")
    } else {
        HttpResponse::Unauthorized().body("Invalid password")
    }
}

#[derive(serde::Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
    confirm_password: String,
    phone_number: String,
}

#[derive(serde::Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
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
