use std::env;


pub struct Config {
  pub database_url: String,
  pub host: String,
  pub port: u16,
}


impl Config {

  pub fn from_env() -> Self {
    dotenvy::dotenv().ok();
    Self {
      database_url: env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env."),
      host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
      port: env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        // Si le port n'est pas definit dans le .env alors on prend une valeur par defaut.
        .parse()
        .expect("The port must be a number."),
    }
  }
}
