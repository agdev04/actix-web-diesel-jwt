
use actix_web::web;
use super::handler::login;

pub fn auth_default_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
    web::scope("/auth")
      .route("/login", web::post().to(login))
  );
}