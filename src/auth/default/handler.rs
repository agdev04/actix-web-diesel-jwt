
use actix_web::{web, HttpResponse, Result};
use serde_json::json;
use crate::auth::authenticate_user;
use crate::users::handler::LoginUser;


pub async fn login(user: web::Json<LoginUser>) -> Result<HttpResponse> {

  match authenticate_user(user).await {
      Ok(token) => {
          Ok(HttpResponse::Ok().json(json!({
              "status": "success",
              "message": "User logged in successfully",
              "token": token
          })))
      },
      Err(_) => Ok(HttpResponse::Unauthorized().json(json!({
          "status": "error",
          "message": "Invalid email or password"
      })))
  }
}
