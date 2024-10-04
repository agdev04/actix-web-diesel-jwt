use std::env;

// Initialize the logger

pub fn get_auth_setup() -> String {
    // Load .env file
  dotenv::dotenv().ok();
  
  // Attempt to get AUTH_SETUP from environment
  let auth_setup = env::var("AUTH_SETUP").unwrap_or_else(|_| {
      println!("AUTH_SETUP not found in environment. Using default value.");
      "default".to_string()
  });
  
  auth_setup
}
