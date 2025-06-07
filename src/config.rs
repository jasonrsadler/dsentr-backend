use std::env;

pub struct Config {
    pub database_url: String,
    pub frontend_origin: String,
}

impl Config {
    pub fn from_env() -> Self {
        dotenv::dotenv().ok(); // Load .env file

        let database_url = env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set");

        let frontend_origin = env::var("FRONTEND_ORIGIN")
            .expect("FRONTEND_ORIGIN must be set");

        Config {
            database_url,
            frontend_origin
        }
    }
}
