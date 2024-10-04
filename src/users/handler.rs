use actix_web::{HttpMessage, HttpRequest};
use actix_web::{web, HttpResponse, Result};
use argon2::Argon2;
use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
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

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub company: String,
    pub exp: usize,
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