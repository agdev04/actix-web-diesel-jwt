use std::env;

use actix_web::{
  body::MessageBody, dev::{ServiceRequest, ServiceResponse}, middleware::Next, Error, HttpMessage,
};
use actix_web::error::ErrorUnauthorized;
use jsonwebtoken::{errors::ErrorKind, Algorithm, Validation, decode, DecodingKey};

use crate::users::handler::Claims;

pub async fn my_midleware(
  req: ServiceRequest,
  next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
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