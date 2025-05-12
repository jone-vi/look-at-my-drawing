use std::env;
use actix_web::{web, App, HttpServer};
use auth_service::{auth::JWTAuth, db::Database, handlers::{register, login, some_operation, AppState}};
use dotenv::dotenv;

#[actix_web::main]
async fn main() -> std::io::Result<()>{
    dotenv().ok();
    env_logger::init();

    let database_url = env::var("DATABASE_URL")
        .expect("ENV: DATABASE_URL needs to be set");

    let jwt_secret = env::var("JWT_SECRET")
        .expect("ENV: JWT_SECRET needs to be set");

    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let server_url = format!("{}:{}", host, port);

    let db = Database::new(&database_url)
        .await
        .expect("Failed to connect to the database");

    db.init_schema()
        .await
        .expect("Failed to initialize the database schema");

    let auth = JWTAuth::new(jwt_secret);

    let app_state = web::Data::new(AppState { db, auth });

    println!("Starting server at http://{}", server_url);

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
            .route("/some-operation", web::post().to(some_operation))
    })
    .bind(server_url)?
    .run()
    .await
}
