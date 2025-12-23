//! Zcash Enclave API Controller
//! 
//! REST API endpoints for:
//! - Generating deposit addresses
//! - Scanning for deposits (with direct minting)
//! - Enclave status

use actix_web::{get, post, web, HttpResponse, Responder};
use anyhow::{Context, Result};
use prost::Message;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use std::sync::Arc;

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
pub struct ScanBlocksRequest {
    pub start_height: u64,
    pub end_height: u64,
}

#[derive(Debug, Deserialize)]
pub struct DepositIntentRequest {
    pub solana_pubkey: String,
    pub diversifier_index: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct ProvisionEnclaveRequest {
    pub ufvk: String,
    pub bridge_ua: String,
}

#[derive(Debug, Serialize)]
pub struct ProvisionEnclaveResponse {
    pub enclave_pubkey: String,
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
    
    let provisioned = service.enclave_provisioner.is_provisioned();
    let ready = service.is_ready();
    let can_mint = service.can_mint();
    
    HttpResponse::Ok().json(serde_json::json!({
        "provisioned": provisioned,
        "ready": ready,
        "can_mint": can_mint,
        "enclave_pubkey": hex::encode(service.enclave_provisioner.enclave_pubkey_bytes()),
        "last_scanned_height": service.last_scanned_height,
        "note": if can_mint {
            "Enclave is fully operational with direct Solana minting enabled."
        } else if ready {
            "Enclave ready for scanning but Solana minting not configured. Set --program-id to enable."
        } else if provisioned {
            "UFVK is sealed but scanner not initialized."
        } else {
            "Enclave not yet provisioned. Waiting for MPC nodes to call POST /v1/provision."
        }
    }))
}

/// Scan blocks for deposits and mint directly
#[post("/v1/scan")]
pub async fn scan_blocks(
    controller: web::Data<Arc<ZCashController>>,
    body: web::Json<ScanBlocksRequest>,
) -> impl Responder {
    let mut service = controller.zcash_service.lock().await;
    
    if !service.is_ready() {
        return HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "Enclave not provisioned. MPC nodes must complete DKG and call POST /v1/provision first.",
            "provisioned": service.enclave_provisioner.is_provisioned()
        }));
    }
    
    match service.scan_blocks(body.start_height, body.end_height).await {
        Ok(processed) => {
            let minted = processed.iter()
                .filter(|p| p.mint_result.as_ref().map(|r| r.success).unwrap_or(false))
                .count();
            let failed = processed.iter()
                .filter(|p| p.error.is_some())
                .count();
            
            HttpResponse::Ok().json(serde_json::json!({
                "blocks_scanned": body.end_height - body.start_height + 1,
                "deposits_found": processed.len(),
                "minted": minted,
                "failed": failed,
                "deposits": processed.iter().map(|p| {
                    serde_json::json!({
                        "note_commitment": hex::encode(p.attestation.note_commitment),
                        "amount": p.attestation.amount,
                        "recipient_solana": hex::encode(p.attestation.recipient_solana),
                        "block_height": p.attestation.block_height,
                        "enclave_signature": hex::encode(p.attestation.enclave_signature),
                        "minted": p.mint_result.as_ref().map(|r| r.success).unwrap_or(false),
                        "tx_signature": p.mint_result.as_ref().map(|r| r.signature.clone()),
                        "error": p.error.clone()
                    })
                }).collect::<Vec<_>>()
            }))
        }
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            }))
        }
    }
}

/// Get pending attestations - DEPRECATED
/// With direct minting, attestations are submitted immediately during scanning.
#[get("/v1/attestations/pending")]
pub async fn get_pending_attestations(
    _controller: web::Data<Arc<ZCashController>>,
) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "attestations": [],
        "note": "DEPRECATED: Attestations are now submitted directly during scanning."
    }))
}

/// Mark attestation as submitted - DEPRECATED
/// With direct minting, this is no longer needed.
#[post("/v1/attestations/mark-submitted")]
pub async fn mark_attestation_submitted(
    _controller: web::Data<Arc<ZCashController>>,
    _body: web::Json<serde_json::Value>,
) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "deprecated",
        "note": "Attestations are now submitted directly during scanning."
    }))
}

/// Create deposit intent (generate address and track)
#[post("/v1/deposit-intents")]
pub async fn create_deposit_intent(
    controller: web::Data<Arc<ZCashController>>,
    body: web::Json<DepositIntentRequest>,
) -> impl Responder {
    let mut service = controller.zcash_service.lock().await;
    
    if !service.is_ready() {
        return HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "Enclave not provisioned"
        }));
    }
    
    match service.connect_wallet(body.solana_pubkey.clone()).await {
        Ok(resp) => HttpResponse::Ok().json(serde_json::json!({
            "deposit_id": format!("dep_{}", resp.diversifier_index),
            "unified_address": resp.deposit_address,
            "diversifier_index": resp.diversifier_index,
            "solana_pubkey": resp.solana_pubkey,
            "status": "pending"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        }))
    }
}

/// Get deposit intent by ID
#[get("/v1/deposit-intents/{deposit_id}")]
pub async fn get_deposit_intent(
    _controller: web::Data<Arc<ZCashController>>,
    path: web::Path<String>,
) -> impl Responder {
    let deposit_id = path.into_inner();
    
    let div_index: u32 = deposit_id
        .strip_prefix("dep_")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    
    HttpResponse::Ok().json(serde_json::json!({
        "deposit_id": deposit_id,
        "diversifier_index": div_index,
        "status": "pending",
        "note": "Full deposit tracking not yet implemented"
    }))
}

/// Provision the enclave with UFVK from MPC nodes
#[post("/v1/provision")]
pub async fn provision_enclave(
    controller: web::Data<Arc<ZCashController>>,
    body: web::Json<ProvisionEnclaveRequest>,
) -> impl Responder {
    let mut service = controller.zcash_service.lock().await;
    
    let req = crate::manager::ProvisionRequest {
        ufvk: body.ufvk.clone(),
        bridge_ua: body.bridge_ua.clone(),
        admin_signature: "mpc_provision".to_string(),
    };
    
    match service.enclave_provisioner.provision(req).await {
        Ok(resp) => {
            if let Err(e) = service.init_after_provisioning().await {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Provisioning succeeded but initialization failed: {}", e),
                    "enclave_pubkey": resp.enclave_pubkey
                }));
            }
            
            HttpResponse::Ok().json(ProvisionEnclaveResponse {
                enclave_pubkey: resp.enclave_pubkey,
                status: "provisioned_and_ready".to_string(),
            })
        },
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
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

#[post("/api/v1/generate-address")]
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
    _controller: web::Data<Arc<ZCashController>>,
    _query: web::Json<BindingRequest>,
) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "not_implemented"
    }))
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
        "status": "not_implemented",
        "note": "Withdrawals are handled by MPC nodes"
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
        "status": "deprecated",
        "note": "Attestations are now submitted directly during scanning"
    }))
}