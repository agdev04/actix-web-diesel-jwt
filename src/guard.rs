

use actix_web::{middleware::from_fn, web};
use crate::{upload::route::upload_config, users::route::user_config};

use std::env;

use actix_web::{
  body::MessageBody, dev::{ServiceRequest, ServiceResponse}, middleware::Next, Error, HttpMessage,
};
use actix_web::error::ErrorUnauthorized;
use jsonwebtoken::{errors::ErrorKind, Algorithm, Validation, decode, DecodingKey};
use crate::users::handler::Claims;
use crate::config::get_auth_setup;

async fn get_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {

    match get_auth_setup().as_str() {
        "http_only" => {
          let cookie = req.cookie("jwt");

          match cookie {
              Some(cookie) => {

                  let key = env::var("AUTH_TOKEN").unwrap_or_else(|_| "secret".to_string());
                  let key = key.as_bytes();

                  let token = cookie.value();

                  let mut validation = Validation::new(Algorithm::HS256);
                  validation.sub = Some("someone".to_string());
                  validation.set_required_spec_claims(&["exp", "sub"]);

                  match decode::<Claims>(token, &DecodingKey::from_secret(key), &validation) {
                      Ok(token_data) => {
                        req.extensions_mut().insert(token_data.claims.company.clone());
                        next.call(req).await
                      }
                      Err(err) => match *err.kind() {
                          ErrorKind::InvalidToken => Err(ErrorUnauthorized("Invalid token")),
                          ErrorKind::InvalidIssuer => Err(ErrorUnauthorized("Invalid issuer")),
                          _ => Err(ErrorUnauthorized("Authentication failed")),
                      },
                  }
              }
              None => Err(ErrorUnauthorized("No authorization header")),
          }
        }
        _ => {
          let auth_header = req.headers().get("Authorization");

          match auth_header {
              Some(auth_value) => {
                  let auth_str = auth_value.to_str().map_err(|_| ErrorUnauthorized("Invalid authorization header"))?;
                  if !auth_str.starts_with("Bearer ") {
                      return Err(ErrorUnauthorized("Invalid authorization header format"));
                  }
                  let token = &auth_str[7..]; // Skip "Bearer " prefix

                  let key = env::var("AUTH_TOKEN").unwrap_or_else(|_| "secret".to_string());
                  let key = key.as_bytes();

                  let mut validation = Validation::new(Algorithm::HS256);
                  validation.sub = Some("someone".to_string());
                  validation.set_required_spec_claims(&["exp", "sub"]);

                  match decode::<Claims>(token, &DecodingKey::from_secret(key), &validation) {
                      Ok(token_data) => {
                          req.extensions_mut().insert(token_data.claims.company.clone());
                          next.call(req).await
                      }
                      Err(err) => match *err.kind() {
                          ErrorKind::InvalidToken => Err(ErrorUnauthorized("Invalid token")),
                          ErrorKind::InvalidIssuer => Err(ErrorUnauthorized("Invalid issuer")),
                          _ => Err(ErrorUnauthorized("Authentication failed")),
                      },
                  }
              }
              None => Err(ErrorUnauthorized("No authorization header")),
          }
        },
    }
}

pub fn guard_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
    web::scope("")
    .wrap(from_fn(get_middleware))
    .configure(user_config)
    .configure(upload_config)
  );
}
