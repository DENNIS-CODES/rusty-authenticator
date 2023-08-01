use regex::Regex;
use validator::validate_email;

pub fn is_valid_username(username: &str) -> bool {
    username.len() >= 3 && username.len() <= 20
}
pub fn is_valid_phone_number(phone_number: &str) -> bool {
    let phone_number_regex = Regex::new(r"^(?:\+254|07|7)\d{8}$").unwrap();
    phone_number_regex.is_match(phone_number)
}

pub fn is_valid_password(password: &str, confirm_password: &str) -> Result<(), &'static str> {
    if password.len() < 8 
    || !password.chars().any(char::is_uppercase)
    || !password.chars().any(char::is_lowercase)
    || !password.chars().any(char::is_numeric)
    {
        return Err("Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter and one number");
    }
    if password != confirm_password {
        return Err("Passwords do not match");
    }
    Ok(())
}

pub fn is_valid_email(email: &str) -> bool {
   validate_email(email)
}