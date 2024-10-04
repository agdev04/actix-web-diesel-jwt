use actix_web::{middleware::from_fn, web};

use crate::users::{middleware::my_midleware, handler::{create_user, delete_user, get_user, get_users, update_user, logout}} ;


pub fn user_config(cfg: &mut web::ServiceConfig) {

    cfg.service(
    web::scope("/users")
      .wrap(from_fn(my_midleware))
      .route("/", web::get().to(get_users))
      .route("/", web::post().to(create_user))
      .route("/{id}", web::get().to(get_user))
      .route("/{id}", web::put().to(update_user))
      .route("/{id}", web::delete().to(delete_user))
      .route("/auth/logout", web::get().to(logout))
  );
}
