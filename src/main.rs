use actix_web::{web, App, HttpResponse, HttpServer};
use bcrypt::{hash, verify, DEFAULT_COST};
use std::sync::Mutex;
// In-memory storage for simplicity
struct AppState {
    users: Mutex<Vec<User>>,
}

struct User {
    username: String,
    password_hash: String,
}

async fn register_user(data: web::Json<RegisterRequest>, state: web::Data<AppState>) -> HttpResponse {
    let mut users = state.users.lock().unwrap();

    // Check if the username is already taken
    if users.iter().any(|user| user.username == data.username) {
        return HttpResponse::Conflict().body("Username already taken");
    }

    // Hash the password
    let password_hash = match hash(&data.password, DEFAULT_COST) {
        Ok(hash) => hash,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    // Create a new user
    let user = User {
        username: data.username.clone(),
        password_hash,
    };

    // Store the user in the state
    users.push(user);

    HttpResponse::Ok().body("User registered successfully")
}

async fn login_user(data: web::Json<LoginRequest>, state: web::Data<AppState>) -> HttpResponse {
    let users = state.users.lock().unwrap();

    // Find the user by username
    let user = match users.iter().find(|user| user.username == data.username) {
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
}

#[derive(serde::Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Create the initial state
    let app_state = web::Data::new(AppState { users: Mutex::new(vec![]) });

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
