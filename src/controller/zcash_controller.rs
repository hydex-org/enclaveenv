//! Zcash Enclave API Controller
//! 
//! REST API endpoints for:
//! - Generating deposit addresses
//! - Scanning for deposits
//! - Getting pending attestations
//! - Enclave status

use actix_web::{get, post, web, HttpResponse, Responder};
use anyhow::{Context, Result};
use prost::Message;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use std::sync::Arc;

use crate::manager::DepositAttestation;
use crate::service::ZCashRpcClientService;

// ============================================================================
// CONTROLLER
// ============================================================================

pub struct ZCashController {
    pub zcash_service: Arc<Mutex<ZCashRpcClientService>>,
}

impl ZCashController {
    pub async fn new() -> Result<Self> {
        let zcash_service = ZCashRpcClientService::new()
            .await
            .context("Failed to initialize ZCash RPC Service")?;

        Ok(Self {
            zcash_service: Arc::new(Mutex::new(zcash_service)),
        })
    }
}

// ============================================================================
// REQUEST/RESPONSE TYPES
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct SolanaWalletRequest {
    pub solana_wallet: String,
}

#[derive(Debug, Deserialize)]
pub struct GenerateAddressRequest {
    pub solana_pubkey: String,
}

#[derive(Debug, Serialize)]
pub struct GenerateAddressResponse {
    pub unified_address: String,
    pub diversifier_index: u32,
    pub solana_pubkey: String,
}

#[derive(Debug, Deserialize)]
pub struct ScanBlocksRequest {
    pub start_height: u64,
    pub end_height: u64,
}

#[derive(Debug, Serialize)]
pub struct ScanResultResponse {
    pub blocks_scanned: u64,
    pub deposits_found: usize,
    pub attestations: Vec<AttestationResponse>,
}

#[derive(Debug, Serialize)]
pub struct AttestationResponse {
    pub note_commitment: String,
    pub amount: u64,
    pub recipient_solana: String,
    pub block_height: u64,
    pub enclave_signature: String,
    pub enclave_pubkey: String,
}

impl From<&DepositAttestation> for AttestationResponse {
    fn from(a: &DepositAttestation) -> Self {
        Self {
            note_commitment: hex::encode(a.note_commitment),
            amount: a.amount,
            recipient_solana: hex::encode(a.recipient_solana),
            block_height: a.block_height,
            enclave_signature: hex::encode(a.enclave_signature),
            enclave_pubkey: hex::encode(a.enclave_pubkey),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct EnclaveStatusResponse {
    pub provisioned: bool,
    pub enclave_pubkey: String,
    pub pending_attestations: usize,
    pub last_scanned_height: u64,
}

#[derive(Debug, Deserialize)]
pub struct DepositIntentRequest {
    pub solana_pubkey: String,
    pub diversifier_index: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct DepositIntentResponse {
    pub deposit_id: String,
    pub unified_address: String,
    pub diversifier_index: u32,
    pub status: String,
}

// ============================================================================
// ENDPOINTS
// ============================================================================

/// Health check
#[get("/health")]
pub async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "service": "zcash-enclave"
    }))
}

/// Get enclave status
#[get("/v1/status")]
pub async fn get_status(
    controller: web::Data<Arc<ZCashController>>,
) -> impl Responder {
    let service = controller.zcash_service.lock().await;
    
    let response = EnclaveStatusResponse {
        provisioned: service.enclave_provisioner.is_provisioned(),
        enclave_pubkey: hex::encode(service.enclave_provisioner.enclave_pubkey_bytes()),
        pending_attestations: service.get_pending_attestations().len(),
        last_scanned_height: service.last_scanned_height,
    };
    
    HttpResponse::Ok().json(response)
}

/// Generate a deposit address for a Solana user
#[post("/v1/generate-address")]
pub async fn generate_address(
    controller: web::Data<Arc<ZCashController>>,
    body: web::Json<GenerateAddressRequest>,
) -> impl Responder {
    let service = controller.zcash_service.lock().await;
    
    match service.generate_deposit_address(&body.solana_pubkey) {
        Ok((unified_address, diversifier_index)) => {
            HttpResponse::Ok().json(GenerateAddressResponse {
                unified_address,
                diversifier_index,
                solana_pubkey: body.solana_pubkey.clone(),
            })
        }
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            }))
        }
    }
}

/// Scan blocks for deposits
#[post("/v1/scan")]
pub async fn scan_blocks(
    controller: web::Data<Arc<ZCashController>>,
    body: web::Json<ScanBlocksRequest>,
) -> impl Responder {
    let mut service = controller.zcash_service.lock().await;
    
    match service.scan_blocks(body.start_height, body.end_height).await {
        Ok(attestations) => {
            let response = ScanResultResponse {
                blocks_scanned: body.end_height - body.start_height + 1,
                deposits_found: attestations.len(),
                attestations: attestations.iter().map(AttestationResponse::from).collect(),
            };
            HttpResponse::Ok().json(response)
        }
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            }))
        }
    }
}

/// Get pending attestations (ready for Solana submission)
#[get("/v1/attestations/pending")]
pub async fn get_pending_attestations(
    controller: web::Data<Arc<ZCashController>>,
) -> impl Responder {
    let service = controller.zcash_service.lock().await;
    let attestations = service.get_pending_attestations();
    
    let response: Vec<AttestationResponse> = attestations
        .iter()
        .map(AttestationResponse::from)
        .collect();
    
    HttpResponse::Ok().json(response)
}

/// Mark attestation as submitted (remove from queue)
#[post("/v1/attestations/mark-submitted")]
pub async fn mark_attestation_submitted(
    controller: web::Data<Arc<ZCashController>>,
    body: web::Json<serde_json::Value>,
) -> impl Responder {
    let note_commitment_hex = match body.get("note_commitment").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "note_commitment required"
            }));
        }
    };
    
    let note_commitment_bytes = match hex::decode(note_commitment_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "invalid note_commitment format"
            }));
        }
    };
    
    let service = controller.zcash_service.lock().await;
    service.mark_attestation_submitted(&note_commitment_bytes);
    
    HttpResponse::Ok().json(serde_json::json!({
        "status": "removed"
    }))
}

/// Create deposit intent (generate address and track)
#[post("/v1/deposit-intents")]
pub async fn create_deposit_intent(
    controller: web::Data<Arc<ZCashController>>,
    body: web::Json<DepositIntentRequest>,
) -> impl Responder {
    let service = controller.zcash_service.lock().await;
    
    match service.generate_deposit_address(&body.solana_pubkey) {
        Ok((unified_address, diversifier_index)) => {
            HttpResponse::Ok().json(DepositIntentResponse {
                deposit_id: format!("dep_{}", diversifier_index),
                unified_address,
                diversifier_index,
                status: "pending".to_string(),
            })
        }
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            }))
        }
    }
}

/// Get deposit intent by ID
#[get("/v1/deposit-intents/{deposit_id}")]
pub async fn get_deposit_intent(
    controller: web::Data<Arc<ZCashController>>,
    path: web::Path<String>,
) -> impl Responder {
    let deposit_id = path.into_inner();
    
    // Parse diversifier index from deposit_id (format: dep_N)
    let div_index: u32 = deposit_id
        .strip_prefix("dep_")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    
    // For now, return a placeholder
    // In production, you'd look up the actual deposit status
    HttpResponse::Ok().json(serde_json::json!({
        "deposit_id": deposit_id,
        "diversifier_index": div_index,
        "status": "pending",
        "note": "Deposit tracking not fully implemented"
    }))
}

// ============================================================================
// LEGACY ENDPOINTS (kept for compatibility)
// ============================================================================

#[derive(Deserialize)]
struct EmitOrchardQuery {
    data: Vec<u8>,
    height: u64,
}

#[post("/zec/emit_orchard")]
pub async fn emit_orchard(
    controller: web::Data<Arc<ZCashController>>,
    query: web::Json<EmitOrchardQuery>,
) -> impl Responder {
    let mut service = controller.zcash_service.lock().await;

    match service.emit_orchard(query.data.clone(), query.height).await {
        Ok(block_json) => {
            let body_bytes = block_json.encode_to_vec();
            HttpResponse::Ok()
                .content_type("application/octet-stream")
                .json(body_bytes)
        }
        Err(e) => {
            HttpResponse::InternalServerError().body(format!("Failed: {}", e))
        }
    }
}

#[post("/api/v1/connect_wallet")]
pub async fn connect_wallet(
    controller: web::Data<Arc<ZCashController>>,
    query: web::Json<SolanaWalletRequest>,
) -> impl Responder {
    let mut service = controller.zcash_service.lock().await;

    match service.connect_wallet(query.solana_wallet.clone()).await {
        Ok(r) => HttpResponse::Ok().json(r),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

#[derive(Deserialize)]
pub struct BindingRequest {
    solana_wallet: String,
    deposit_address: String,
}

#[post("/v1/auth/challenge")]
pub async fn auth_challenge(
    controller: web::Data<Arc<ZCashController>>,
    query: web::Json<BindingRequest>,
) -> impl Responder {
    let mut service = controller.zcash_service.lock().await;

    match service.auth_challenge(query.solana_wallet.clone(), query.deposit_address.clone()).await {
        Ok(r) => HttpResponse::Ok().json(r),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

#[post("/v1/auth/verify-wallet")]
pub async fn verify_wallet(
    _controller: web::Data<Arc<ZCashController>>,
) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "not_implemented"
    }))
}

#[post("/v1/burn-intents")]
pub async fn burn_intents(
    _controller: web::Data<Arc<ZCashController>>,
) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "not_implemented"
    }))
}

#[get("/v1/burn-intents/{burn_id}")]
pub async fn get_burn_intent(
    path: web::Path<String>,
) -> impl Responder {
    let burn_id = path.into_inner();
    HttpResponse::Ok().json(serde_json::json!({
        "burn_id": burn_id,
        "status": "not_implemented"
    }))
}

#[post("/v1/internal/attestations")]
pub async fn internal_attestations(
    _controller: web::Data<Arc<ZCashController>>,
) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "not_implemented"
    }))
}