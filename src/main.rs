mod responses;
mod state;
mod config;
mod routes;
pub mod utils;
mod models;

use axum::{
    response::{
        IntoResponse, Response
    }, routing::{get, post}, Router
};
use axum::http::Method;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::HeaderValue;
use responses::JsonResponse;
use sqlx::PgPool;
use tokio::net::TcpListener;
use std::{sync::Arc, net::SocketAddr};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use tower_http::cors::CorsLayer;
use config::Config;
use routes::{auth::{handle_logout, handle_me}, dashboard::dashboard_handler, early_access::handle_early_access};
use routes::auth::{handle_login, handle_signup, verify_email};

use crate::utils::email::Mailer;
use crate::state::AppState;

#[cfg(feature = "tls")]
use axum_server::tls_rustls::RustlsConfig;

#[tokio::main]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let config = Config::from_env();
    let pool = establish_connection(&config.database_url).await;

    // Initialize mailer
    let mailer = Arc::new(Mailer::new().expect("Failed to initialize mailer"));

    let state = AppState {
        db: pool.clone(),
        mailer,
    };

    let cors = CorsLayer::new()
        .allow_origin(config.frontend_origin.parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE])
        .allow_credentials(true);

    let app = Router::new()
        .route("/", get(root))
        .route("/api/early-access", post(handle_early_access))
        .route("/api/auth/signup", post(handle_signup))
        .route("/api/auth/login", post(handle_login))
        .route("/api/auth/logout", post(handle_logout))
        .route("/api/auth/verify", post(verify_email))
        .route("/api/auth/me", get(handle_me))
        .route("/api/dashboard", get(dashboard_handler))
        .with_state(state)
        .layer(cors);

    let make_service = app.into_make_service();
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    #[cfg(feature = "tls")]
    {
        // TLS: Only run this block when `--features tls` is used
        let tls_config = RustlsConfig::from_pem_file(
                std::env::var("DEV_CERT_LOCATION").unwrap(), 
                std::env::var("DEV_KEY_LOCATION").unwrap())
            .await
            .expect("Failed to load TLS certs");

        println!("Running with TLS at https://{}", addr);
        let _ = axum_server::bind_rustls(addr, tls_config)
            .serve(make_service)
            .await;

        return; // Skip the fallback if TLS was used
    }

    let listener = TcpListener::bind(addr).await.unwrap();
    println!("Running without TLS at http://{}", addr);
    axum::serve(listener, make_service)
        .await
        .unwrap();
}
/// A simple root route.
async fn root() -> Response {
    JsonResponse::success("Hello, Dsentr!").into_response()
}

/// Establish a connection to the database and verify it.
async fn establish_connection(database_url: &str) -> PgPool {
    let pool = PgPool::connect(database_url)
        .await
        .expect("Failed to connect to the database");

    sqlx::query("SELECT 1")
        .execute(&pool)
        .await
        .expect("Failed to verify database connection");

    info!("✅ Successfully connected to the database");
    pool
}
