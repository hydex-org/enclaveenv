use actix_web::{App, HttpServer, http, web};
use actix_cors::Cors;
use std::sync::Arc;

mod controller;
mod service;
mod client;
mod scanner;
mod manager;

use crate::controller::ZCashController;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting Zcash Enclave server...");

    let zcash_controller = Arc::new(ZCashController::new().await.unwrap());

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allowed_methods(vec!["GET", "POST", "OPTIONS"])
            .allowed_headers(vec![
                http::header::CONTENT_TYPE,
                http::header::ACCEPT,
            ])
            .max_age(3600);

        App::new()
            .wrap(cors)
            .app_data(web::Data::new(zcash_controller.clone()))
            .service(controller::provision_enclave)
            // Core endpoints
            .service(controller::health_check)
            .service(controller::get_status)
            .service(controller::generate_address)
            .service(controller::scan_blocks)
            .service(controller::get_pending_attestations)
            .service(controller::mark_attestation_submitted)
            .service(controller::create_deposit_intent)
            .service(controller::get_deposit_intent)
            // Legacy endpoints
            .service(controller::emit_orchard)
            .service(controller::connect_wallet)
            .service(controller::auth_challenge)
            .service(controller::verify_wallet)
            .service(controller::burn_intents)
            .service(controller::get_burn_intent)
            .service(controller::internal_attestations)
    })
    .bind("127.0.0.1:8089")?
    .run()
    .await
}