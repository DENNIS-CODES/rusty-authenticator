use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use bcrypt::{hash, verify, DEFAULT_COST};

// In memory storage for simplicity

struct AppState {
    user: Vec<User>,
}

struct User {
    username: String,
    password_hash: String,
}

async fn register_user(data: web::Json<RegisterRequest>, state: web::Data<AppState>) -> HttpResponder {
    let mut users = state.user.lock().unwrap();

    // check if the username is already taken
    if users.iter().any(|user| user.username == data.username) {
        return HttpResponse::BadRequest().body("Username already taken");
    }

    // hash the password
    let password_hash = match hash(&data.password, DEFAULT_COST) {
        Ok(hash) => hash,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to hash password").finish(),
    };
    let user =  User {
        username: data.username.clone(),
        password_hash,
    };
    // store the user in state
    users.push(user);
    HttpResponse::Ok().body("User registered Successfully")
}

async fn login_user(data: web::Json<LoginRequest>, state: web::Data<AppState>) -> HttpResponder {
    let users = state.user.lock().unwrap();

    // find the user
    let user = match users.iter().find(|user| user.username == data.username) {
        Some(user) => user,
        None => return HttpResponse::BadRequest().body("Invalid username or password"),
    };

    // verify the password
    if !verify(&data.password, &user.password_hash).unwrap_or(false) {
        return HttpResponse::BadRequest().body("Invalid username or password");
    }

    HttpResponse::Ok().body("Login Successful")
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
fn main() -> std::io::Result<()> {
    //create initial state
    let app_state = web::Data::new(AppState {
        user: Ve![],
    });

    //start the HTTP server
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .service(
                web::scope("/api")
                    .service(
                        web::resource("/register")
                            .route(web::post().to(register_user))
                    )
                    .service(
                        web::resource("/login")
                            .route(web::post().to(login_user))
                    )
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
