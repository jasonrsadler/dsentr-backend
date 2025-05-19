pub mod signup;
pub mod login;
//pub mod google_login;
pub mod logout;
pub mod verify;
pub mod session;
pub mod claims;
pub mod forgot_password;
pub mod reset_password;

pub use signup::handle_signup;
pub use login::handle_login;
//pub use google_login::google_login;
pub use logout::handle_logout;
pub use login::handle_me;
pub use verify::verify_email;
