use axum::{Router, routing::get};


#[tokio::main]
async fn main() {
  // Construction du routeur
  let app = Router::new()
      .route("/", get(|| async { "Hello, World!" }));

  // Démarrage du serveur sur le port 3000
  let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
  axum::serve(listener, app).await.unwrap();

}
