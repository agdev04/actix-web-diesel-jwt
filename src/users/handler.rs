use std::env;
use actix_web::cookie::SameSite;
use actix_web::{HttpMessage, HttpRequest, cookie::time::Duration};
use actix_web::{web, HttpResponse, Result, cookie::Cookie, error};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use crate::{db::establish_connection, users::model::{NewUser, UpdateUser, User}, schema::users};
use diesel::prelude::*;
use argon2::PasswordHasher;

#[derive(Serialize)]
pub struct GenericResponse {
  pub status: String,
  pub message: String,
}

use jsonwebtoken::{encode, Header, EncodingKey};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub company: String,
    pub exp: usize,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginUser {
    pub email: String,
    pub password: String,
}

pub fn hash_password(password: String) -> Result<String, actix_web::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let hash_result = argon2.hash_password(password.as_bytes(), &salt)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    Ok(hash_result.to_string())
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
        .body("Logged out successfully!"))
}

pub async fn login(user: web::Json<LoginUser>) -> Result<HttpResponse> {

    let mut connection = establish_connection();
    let user_query = users::table.filter(users::email.eq(&user.email)).first(&mut connection);

    let user_result: User = match user_query {
        Ok(user) => user,
        Err(_) => return Ok(HttpResponse::Unauthorized().json(GenericResponse {
            status: "fail".to_string(),
            message: "Invalid email or password".to_string(),
        })),
    };

    let argon2 = Argon2::default();
    let db_hash = PasswordHash::new(&user_result.password).map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    argon2.verify_password(user.password.as_bytes(), &db_hash)
        .map_err(|_| error::ErrorUnauthorized("Invalid email or password"))?;

    let token = create_token(user_result.id).await?;
    
    let cookie = Cookie::build("jwt", token)
        .http_only(true)
        .secure(false)
        .same_site(SameSite::Lax)
        .path("/")
        .finish();

    let mut response = HttpResponse::Ok().json(json!({
        "status": "success",
        "message": "User logged in successfully"
    }));

    response.add_cookie(&cookie)?;

    Ok(response)
  
}

pub async fn create_user(new_user: web::Json<NewUser>) -> Result<HttpResponse> {
  let mut connection = establish_connection();
		
    let hashed_password = hash_password(new_user.password.clone()).unwrap();
    let new_user = NewUser {
        password: hashed_password.to_string(),
        ..new_user.into_inner()
    };  

    diesel::insert_into(users::table)
        .values(&new_user)
        .execute(&mut connection)
        .expect("Error inserting new user");
    Ok(HttpResponse::Ok().json("User created successfully"))
}

pub async fn get_users(req: HttpRequest) -> Result<HttpResponse> {

    let connection = &mut establish_connection();
    let results = users::table
        .load::<User>(connection)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let user_id = req.extensions().get::<String>().cloned().unwrap_or_default();

    Ok(HttpResponse::Ok().json(json!({
        "status": "success",
        "data": results,
        "my_user_id": user_id
    })))
}

pub async fn get_user(id: web::Path<i32>) -> Result<HttpResponse> {
    let mut connection = establish_connection();
    let user_id = id.into_inner();
    let result = users::table
        .find(user_id)
        .first::<User>(&mut connection)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(result))
}

pub async fn update_user(id: web::Path<i32>, user: web::Json<UpdateUser>) -> Result<HttpResponse> {
    let mut connection = establish_connection();
    let user_id = id.into_inner();
    let result = diesel::update(users::table.find(user_id))
        .set(user.into_inner())
        .execute(&mut connection);

    match result {
        Ok(num_updated) => {
            if num_updated > 0 {
                Ok(HttpResponse::Ok().json(GenericResponse {
                    status: "success".to_string(),
                    message: "User updated successfully".to_string(),
                }))
            } else {
                Ok(HttpResponse::NotFound().json(GenericResponse {
                    status: "error".to_string(),
                    message: "User not found".to_string(),
                }))
            }
        },
        Err(_) => Ok(HttpResponse::InternalServerError().json(GenericResponse {
            status: "error".to_string(),
            message: "Failed to update user".to_string(),
        }))
    }
}
        


pub async fn delete_user(id: web::Path<i32>) -> Result<HttpResponse> {
    let mut connection = establish_connection();
    let user_id = id.into_inner();
    let result = diesel::delete(users::table.find(user_id))
        .execute(&mut connection);

    match result {
        Ok(num_deleted) => {
            if num_deleted > 0 {
                Ok(HttpResponse::Ok().json(GenericResponse {
                    status: "success".to_string(),
                    message: "User deleted successfully".to_string(),
                }))
            } else {
                Ok(HttpResponse::NotFound().json(GenericResponse {
                    status: "error".to_string(),
                    message: "User not found".to_string(),
                }))
            }
        },
        Err(_) => Ok(HttpResponse::InternalServerError().json(GenericResponse {
            status: "error".to_string(),
            message: "Failed to delete user".to_string(),
        }))
    }
}