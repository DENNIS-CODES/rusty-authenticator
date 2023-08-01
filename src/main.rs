#[warn(dead_code)]
use actix_web::{web, App, HttpResponse, HttpServer};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::format::ParseError;
use chrono::{offset::Utc, DateTime, Duration, FixedOffset};
use dotenv::dotenv;
use jsonwebtoken::{encode, EncodingKey, Header};
use prisma::PrismaClient;
extern crate serde;

use std::env;
mod types {
    pub mod user;
}
use types::user::{AuthPayload, LoginRequest, LoginResponse, RegisterRequest};

mod middlewares {
    pub mod validation;
}

use middlewares::validation::{
    is_valid_email, is_valid_password, is_valid_phone_number, is_valid_username,
};

#[allow(warnings)]
mod prisma;

fn _string_to_datetime(date_string: &str) -> Result<DateTime<FixedOffset>, ParseError> {
    DateTime::parse_from_rfc3339(date_string)
}
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let client = PrismaClient::_builder()
        .build()
        .await
        .expect("Failed to create Prisma client.");
    let new_user = client
        .user()
        .create(
            "wanda".to_owned(),
            "secret354".to_owned(),
            "dennis@indu.io".to_owned(),
            "0762354261".to_owned(),
            vec![
                prisma::user::id::set(uuid::Uuid::new_v4().to_string()),
                prisma::user::created_at::set(Utc::now().into()),
                prisma::user::updated_at::set(Utc::now().into()),
            ],
        )
        .exec()
        .await;
    println!("{:#?}", new_user);
    HttpServer::new(move || {
        App::new()
            .service(web::resource("/register").route(web::post().to(register_user)))
            .service(web::resource("/login").route(web::post().to(login_user)))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

async fn register_user(
    data: web::Json<RegisterRequest>,
    db: web::Data<PrismaClient>,
) -> HttpResponse {
    if !is_valid_username(&data.username) {
        return HttpResponse::BadRequest().body("Invalid username format");
    }

    let existing_user = db
        .user()
        .find_unique(prisma::user::username::equals(data.username.clone()))
        .exec()
        .await
        .unwrap();

    if existing_user.is_some() {
        return HttpResponse::Conflict().body("Username already taken");
    }

    if !is_valid_phone_number(&data.phone_number) {
        return HttpResponse::BadRequest().body("Invalid phone number format");
    }

    if !is_valid_email(&data.email) {
        return HttpResponse::BadRequest().body("Invalid email format");
    }

    if !is_valid_password(&data.password, &data.confirm_password).is_ok() {
        return HttpResponse::BadRequest().body("Invalid password format");
    }

    let password_hash = match hash(&data.password, DEFAULT_COST) {
        Ok(hash) => hash,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    if data.password != data.confirm_password {
        return HttpResponse::BadRequest().body("Passwords do not match");
    }

    let offset = FixedOffset::east_opt(3 * 3600).expect("Invalid time offset");
    let created_at_fixed_offset = DateTime::<FixedOffset>::from_utc(data.created_at, offset);
    let updated_at_fixed_offset = DateTime::<FixedOffset>::from_utc(data.updated_at, offset);

    let result = db
        .user()
        .create(
            data.username.clone(),
            password_hash,
            data.email.clone(),
            data.phone_number.clone(),
            vec![
                prisma::user::id::set(uuid::Uuid::new_v4().to_string()),
                prisma::user::created_at::set(created_at_fixed_offset),
                prisma::user::updated_at::set(updated_at_fixed_offset),
            ],
        )
        .exec()
        .await;

    match result {
        Ok(_) => HttpResponse::Ok().body("User registered successfully"),
        Err(_) => HttpResponse::InternalServerError().body("Failed to create user"),
    }
}

async fn login_user(data: web::Json<LoginRequest>, db: web::Data<PrismaClient>) -> HttpResponse {
    let user_result = db
        .user()
        .find_unique(prisma::user::username::equals(data.username.clone()))
        .exec()
        .await;

    if let Err(_) = user_result {
        // Error occurred while fetching from the database.
        return HttpResponse::InternalServerError()
            .body("Error occurred while fetching from the database");
    }

    let user = user_result.unwrap(); // Safe to use unwrap here because we've handled the error case above.

    if let Some(user) = user {
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
