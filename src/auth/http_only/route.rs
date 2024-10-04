
use actix_web::web;

use super::handler::{login, logout};

pub fn auth_http_only_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
    web::scope("/auth")
      .route("/login", web::post().to(login))
      .route("/logout", web::post().to(logout))
  );
}