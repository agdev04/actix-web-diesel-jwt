mod schema;

use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use actix_web::middleware::Logger;
use users::handler::{create_user, login};
pub mod users;
pub mod db;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "actix_web=info");
    }

    env_logger::init();

    HttpServer::new(move || {

        let cors = Cors::default()
            .allowed_origin("http://localhost:5173")
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
            .allowed_headers(vec![actix_web::http::header::AUTHORIZATION, actix_web::http::header::ACCEPT])
            .allowed_header(actix_web::http::header::CONTENT_TYPE)
            .supports_credentials();

        App::new()
            .wrap(cors)
            .route("/login", web::post().to(login))
            .route("/register", web::post().to(create_user))
            .configure(users::route::user_config)
            .wrap(Logger::default())
    })
    .bind(("127.0.0.1", 8000))?
    .run()
    .await
}