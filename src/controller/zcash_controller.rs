use actix_web::{HttpResponse, Responder, delete, get, post, put, web};
use anyhow::{Context, Result};
use prost::Message;
use tokio::sync::Mutex;

use crate::{client::wallet::CompactTx, service::ZCashRpcClientService};
use std::sync::Arc;
pub struct ZCashController {
    pub zcash_service: Arc<Mutex<ZCashRpcClientService>>,
}
impl ZCashController {
    // Async constructor
    pub async fn new() -> Result<Self> {
        let zcash_service = ZCashRpcClientService::new()
            .await
            .context("Failed to initialize ZCash RPC Service")?;

        Ok(Self {
            zcash_service: Arc::new(Mutex::new(zcash_service)),
        })
    }
}

#[derive(serde::Deserialize)]
struct PingQuery {
    text: String,
}

// #[get("/ping2")]
// pub async fn ping2(
//     controller: web::Data<Arc<ZCashController>>,
//     query: web::Query<PingQuery>,
// ) -> impl Responder {
//         println!("Ping query reached: {}", query.text);
//     match controller.zcash_service.rpc_client.get_block_count().await {
//         Ok(count) => HttpResponse::Ok().body(count.to_string()),
//         Err(e) => {
//             eprintln!("Failed to get block count: {}", e);
//             HttpResponse::InternalServerError().body("Failed to get block count")
//         }
//     }
// }
// test2

#[derive(serde::Deserialize)]
pub struct solana_wallet_request {
    solana_wallet: String
}

#[post("/api/v1/connect_wallet")]
pub async fn connect_wallet (
    controller: web::Data<Arc<ZCashController>>,
    query: web::Json<EmitOrchardQuery>,
) -> impl Responder {
    HttpResponse::Ok()
}

#[derive(serde::Deserialize)]
struct EmitOrchardQuery {
    data: Vec<u8>,
    height: u64,
}
// inpit #1: blockhash
// input #2: height

#[post("/zec/emit_orchard")]
pub async fn emit_orchard(
    controller: web::Data<Arc<ZCashController>>,
    query: web::Json<EmitOrchardQuery>,
) -> impl Responder {
    //println!("controller.emit_orchard reached");
    // 1. Clone the Arc (cheap, increases ref count)
    let service_arc = controller.zcash_service.clone();

    // 2. Lock the mutex
    let mut service_guard = service_arc.lock().await;

    // 3. Call the method
    match service_guard.emit_orchard(query.data.clone(), query.height).await {
        Ok(block_json) => {
            let body_bytes = block_json.encode_to_vec();
            HttpResponse::Ok()
                .content_type("application/octet-stream")
                .json(body_bytes)
        }
        Err(e) => {
            eprintln!("Error in emit_orchard: {}", e);
            HttpResponse::InternalServerError().body(format!("Failed to emit orchard: {}", e))
        }
    }

}
// connect wallet
#[post("/v1/auth/challenge")]
pub async fn auth_challenge(
    controller: web::Data<Arc<ZCashController>>,
    query: web::Json<EmitOrchardQuery>,
) -> impl Responder {
    HttpResponse::Ok()
}

#[post("/v1/auth/verify-wallet")]
pub async fn verify_wallet(
    controller: web::Data<Arc<ZCashController>>,
    query: web::Json<EmitOrchardQuery>,
) -> impl Responder {
    HttpResponse::Ok()
}

#[post("/v1/deposit-intents")]
pub async fn deposit_intents (
    controller: web::Data<Arc<ZCashController>>,
    query: web::Json<EmitOrchardQuery>,
) -> impl Responder {
    HttpResponse::Ok()
}

#[post("/v1/burn-intents")]
pub async fn burn_intents(
    controller: web::Data<Arc<ZCashController>>,
    query: web::Json<EmitOrchardQuery>,
) -> impl Responder {
    HttpResponse::Ok()
}

// #[get("/v1/deposit-intents")]
// pub async fn deposit_intents(
//     controller: web::Data<Arc<ZCashController>>,
//     query: web::Json<EmitOrchardQuery>,
// ) -> impl Responder {
//     HttpResponse::Ok()
// }

// //#[get("/v1/burn-intents")]
// pub async fn burn_intents(
//     controller: web::Data<Arc<ZCashController>>,
//     query: web::Json<EmitOrchardQuery>,
// ) -> impl Responder {
//     HttpResponse::Ok()
// }

#[get("/v1/deposit-intents/{deposit_id}")]
pub async fn get_deposit_intent (
    controller: web::Data<Arc<ZCashController>>,
    query: web::Json<EmitOrchardQuery>,
) -> impl Responder {
    HttpResponse::Ok()
}

#[post("/v1/internal/attestations")]
pub async fn internal_attestations (
    controller: web::Data<Arc<ZCashController>>,
    query: web::Json<EmitOrchardQuery>,
) -> impl Responder {
    HttpResponse::Ok()
}

#[get("/v1/burn-intents/{burn_id}")]
pub async fn get_burn_intent (
    controller: web::Data<Arc<ZCashController>>,
    query: web::Json<EmitOrchardQuery>,
) -> impl Responder {
    HttpResponse::Ok()
}