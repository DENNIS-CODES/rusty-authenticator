#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use] extern crate rocket;

use rocket::http::cookies;
use rocket::request::{FromForm, Form}};
use rocket::response::{content, Redirect};
use rocket_contrib::templates::Template;
use rocket::State;

#[derive(FromForm)]
struct Login {
    username: String,
    password: String,
}
fn authenticate(login: Login) -> Result<Redirect, Template> {
    if login.username == "admin" && login.password == "password" {
        Ok(Redirect::to("/"))
    } else {
        Err(Template::render("login", {
            let mut context = std::collections::HashMap::new();
            context.insert("error", "Invalid username or password");
            context
        }))
    }
}

#[get("/")]
fn index() -> Template {
    let context = ();
    Template::render("index", &context)
}
#[get("/protected")]
fn protected(cookies: &Cookies) -> Result<content::Html<String>, Redirect> {
    if let Some(auth_cookie) = cookies.get("authenticated") {
        if auth_cookie.value() == "true" {
            let context = ();
            Ok(content::Html(Template::render("protected", &context).to_string()))
        } else {
            Err(Redirect::to("/"))
        }
    } else {
        Err(Redirect::to("/"))
    }
}


fn main() {
    rocket::ignite()
        .attach(Template::fairing())
        .mount("/", routes![index, protected])
        .mount("/", routes![authenticate])
        .launch();
}
