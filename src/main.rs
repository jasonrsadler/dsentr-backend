mod responses;
mod state;
mod config;
mod routes;
pub mod utils;
mod models;
mod db;

use axum::{
    http::HeaderName, response::{
        IntoResponse, Response
    }, routing::{get, post}, Router
};
use axum::http::Method;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::HeaderValue;
use db::postgres_user_repository::PostgresUserRepository;
use responses::JsonResponse;
use sqlx::PgPool;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_governor::{
    governor::GovernorConfigBuilder, 
    GovernorLayer
};
use utils::csrf::{get_csrf_token, validate_csrf};
use std::{net::SocketAddr, sync::Arc};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use tower_http::{
    trace::TraceLayer,
    cors::CorsLayer
};
use config::Config;
use routes::{
    auth::{
        forgot_password::handle_forgot_password, github_login::{github_callback, github_login}, google_login::{
            google_callback, google_login
        }, handle_logout, handle_me, reset_password::{
            handle_reset_password, 
            handle_verify_token
        }
    }, 
    dashboard::dashboard_handler, 
    early_access::handle_early_access
};
use routes::auth::{handle_login, handle_signup, verify_email};

use crate::utils::email::Mailer;
use crate::state::AppState;
use crate::db::user_repository::UserRepository;

#[cfg(feature = "tls")]
use axum_server::tls_rustls::RustlsConfig;

#[tokio::main]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1) // 2 req/sec
            .burst_size(5)
            .use_headers() // optional: adds RateLimit-* headers
            .finish()
            .unwrap(),
    );

    // ✅ Background task to cleanup old IPs
    let governor_limiter = governor_conf.limiter().clone();
    std::thread::spawn(move || {
        let interval = std::time::Duration::from_secs(60);
        loop {
            std::thread::sleep(interval);
            //tracing::info!("Rate limiting map size: {}", governor_limiter.len());
            governor_limiter.retain_recent();
        }
    });

    let rate_limit_ms: u64 = std::env::var("RATE_LIMITER_MILLISECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(500);
    let rate_limit_burst: u32 = std::env::var("RATE_LIMITER_BURST")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(8);
    let global_governor_conf = Arc::new(
    GovernorConfigBuilder::default()
        
        .per_millisecond(rate_limit_ms)
        .burst_size(rate_limit_burst)
        .use_headers()
        .error_handler(|_err| {
            JsonResponse::too_many_requests(
                "Too many requests. Please wait a moment and try again."
            ).into_response()
        })
        .finish()
        .unwrap(),
    );

    let rate_limit_auth_s: u64 = std::env::var("RATE_LIMITER_AUTH_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1);
    let rate_limit_auth_burst: u32 = std::env::var("RATE_LIMITER_AUTH_BURST")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(10);
    // Stricter limiter for /api/auth/*
    let auth_governor_conf = Arc::new(
    GovernorConfigBuilder::default()
        .per_second(rate_limit_auth_s)              
        .burst_size(rate_limit_auth_burst)                                
        .use_headers()                                 
        .error_handler(|_err| {
            JsonResponse::too_many_requests(
                "Too many requests. Please wait a moment and try again."
            ).into_response()
        })
        .finish()
        .unwrap(),
    );
 
    let config = Config::from_env();
    
    let pg_pool = establish_connection(&config.database_url).await;
    let user_repo = Arc::new(PostgresUserRepository { pool: pg_pool.clone() }) as Arc<dyn UserRepository>;

    // Initialize mailer
    let mailer = Arc::new(Mailer::new().expect("Failed to initialize mailer"));

    let state = AppState {
        db: user_repo,
        mailer,
    };

    let cors = CorsLayer::new()
        .allow_origin(config.frontend_origin.parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([
            AUTHORIZATION, 
            CONTENT_TYPE, 
            HeaderName::from_static("x-csrf-token")
        ])
        .allow_credentials(true);

    let csrf_layer = 
        ServiceBuilder::new().layer(axum::middleware::from_fn(validate_csrf));

    // Routes that require CSRF protection (typically unsafe HTTP methods)
    let csrf_protected_routes = Router::new()
        .route("/signup", post(handle_signup))
        .route("/login", post(handle_login))
        .route("/logout", post(handle_logout))
        .route("/verify", post(verify_email))
        .route("/forgot-password", post(handle_forgot_password))
        .route("/reset-password", post(handle_reset_password))
        .layer(csrf_layer.clone()) // Apply CSRF middleware here
        .layer(GovernorLayer { config: auth_governor_conf.clone() });

    // Routes that do NOT require CSRF (safe methods and OAuth)
    let unprotected_routes = Router::new()
        .route("/me", get(handle_me))
        .route("/csrf-token", get(get_csrf_token))
        .route("/google-login", get(google_login))
        .route("/github-login", get(github_login))
        .route("/google-callback", get(google_callback))
        .route("/github-callback", get(github_callback))
        .route("/verify-reset-token/{token}", get(handle_verify_token));

    // Nest them together
    let auth_routes = csrf_protected_routes
        .merge(unprotected_routes)
        .layer(GovernorLayer { config: auth_governor_conf.clone() });

    let app = Router::new()
        .route("/", get(root))
        .route("/api/early-access", post(handle_early_access))
        .route("/api/dashboard", get(dashboard_handler))
        .nest("/api/auth", auth_routes) // <-- your auth routes with CSRF selectively applied
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(GovernorLayer { config: global_governor_conf.clone() })
        .layer(cors);


    let make_service = 
        app.into_make_service_with_connect_info::<SocketAddr>();
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
