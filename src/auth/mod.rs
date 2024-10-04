
use std::env;
use actix_web::cookie::SameSite;
use actix_web::{web, Result, cookie::Cookie, error};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use chrono::Utc;
use crate::users::handler::{Claims, LoginUser};
use crate::{db::establish_connection, users::model::User, schema::users};
use diesel::prelude::*;
use argon2::PasswordHasher;
use jsonwebtoken::{encode, Header, EncodingKey};

pub mod http_only;
pub mod default;

pub fn hash_password(password: String) -> Result<String, actix_web::Error> {
  let salt = SaltString::generate(&mut OsRng);
  let argon2 = Argon2::default();

  let hash_result = argon2.hash_password(password.as_bytes(), &salt)
      .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
  Ok(hash_result.to_string())
}

pub async fn generate_token(token: String) -> Result<Cookie<'static>, actix_web::Error> {
    
  let cookie = Cookie::build("jwt", token)
      .http_only(true)
      .secure(false)
      .same_site(SameSite::Lax)
      .path("/")
      .finish();

  Ok(cookie)
}

async fn authenticate_user(user: web::Json<LoginUser>) -> Result<String, actix_web::Error> {

  let mut connection = establish_connection();
  let user_query = users::table.filter(users::email.eq(&user.email)).first(&mut connection);

  let user_result: User = match user_query {
      Ok(user) => user,
      Err(_) => return Err(actix_web::error::ErrorUnauthorized("Invalid email or password")),
  };

  let argon2 = Argon2::default();
  let db_hash = PasswordHash::new(&user_result.password).map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

  argon2.verify_password(user.password.as_bytes(), &db_hash)
      .map_err(|_| error::ErrorUnauthorized("Invalid email or password"))?;


  // Generate the token
  let token = create_token(user_result.id).await?;

  Ok(token)
}

async fn create_token(user_id: i32) -> Result<String, actix_web::Error> {
  let expiration = Utc::now()
      .checked_add_signed(chrono::Duration::seconds(3600))
      .expect("valid timestamp")
      .timestamp();
  
  let my_claims = Claims {
      sub: "someone".to_owned(),
      company: user_id.to_string(),
      exp: expiration as usize,
  };

  let key = env::var("AUTH_TOKEN").unwrap_or_else(|_| "secret_token".to_string());

  let token = encode(&Header::default(), &my_claims, &EncodingKey::from_secret(key.as_bytes()))
      .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
  
  Ok(token)
}