
use actix_web::cookie::{Cookie, time::Duration};
use actix_web::{web, HttpResponse, Result};
use serde_json::json;
use crate::auth::{authenticate_user, generate_token};
use crate::users::handler::LoginUser;

pub async fn login(user: web::Json<LoginUser>) -> Result<HttpResponse> {
    
  match authenticate_user(user).await {
      Ok(token) => {  
          let cookie = generate_token(token).await?;
          Ok(HttpResponse::Ok()
          .cookie(cookie)
          .json(json!({
              "status": "success",
              "message": "User logged in successfully"
          })))
      },
      Err(_) => Ok(HttpResponse::Unauthorized().json(json!({
          "status": "error",
          "message": "Invalid email or password"
      })))
  }
}

pub async fn logout() -> Result<HttpResponse> {
  let cookie = Cookie::build("jwt", "")
      .http_only(true)
      .secure(false)
      .max_age(Duration::seconds(-3600))
      .path("/")
      .finish();

  Ok(HttpResponse::Ok()
      .cookie(cookie)
      .json(json!({
          "status": "success",
          "message": "User logged out successfully"
      })))
}