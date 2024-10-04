use actix_web::web;

use super::handler::upload_file;

pub fn upload_config(cfg: &mut web::ServiceConfig) {
  
    cfg.service(
    web::scope("/upload")
      .route("", web::post().to(upload_file))
  );
}