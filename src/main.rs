mod config;
mod routes;

use axum::{
    routing::{get, post},
    Router
};
use http::{Method, header::HeaderValue};
use sqlx::PgPool;
use std::net::SocketAddr;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use tower_http::cors::{CorsLayer, Any};

use config::Config;
use routes::early_access::handle_early_access;

#[tokio::main]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let cfg = Config::from_env();

    let pool = establish_connection().await;

    let cors = CorsLayer::new()
        .allow_origin([HeaderValue::from_str(&cfg.frontend_origin).unwrap()])
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(root))
        .route("/api/early-access", post(handle_early_access))
        .with_state(pool); // ✅ attach state here

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    info!("Listening on http://{}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn root() -> &'static str {
    "Hello, Dsentr!"
}

async fn establish_connection() -> PgPool {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to the database");

    sqlx::query("SELECT 1")
        .execute(&pool)
        .await
        .expect("Failed to verify database connection");

    info!("✅ Successfully connected to the database");
    pool
}
