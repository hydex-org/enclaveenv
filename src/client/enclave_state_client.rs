// ! Zcash Enclave REST API Server
// !
// ! Endpoints:
// ! - POST /provision          - Provision enclave with UFVK from MPC
// ! - POST /generate-address   - Generate diversified deposit address
// ! - GET  /status             - Check provisioning status
// ! - GET  /health             - Health check

use anyhow::Result;
use axum::{
    extract::{Json, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, error};

use crate::manager::{AddressManager, EnclaveProvisioner, ProvisionRequest, ProvisionResponse};

/// Shared state across all handlers
#[derive(Clone)]
pub struct EnclaveStateClient {
    pub provisioner: Arc<EnclaveProvisioner>,
    pub address_manager: Arc<tokio::sync::Mutex<Option<AddressManager>>>,
}

impl EnclaveStateClient {
    pub async fn new() -> Result<Self> {
        // Initialize tracing
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("zcash_enclave=info".parse()?)
            )
            .init();

        println!("╔════════════════════════════════════════════════════╗");
        println!("║     Zcash Enclave Service Starting...              ║");
        println!("╚════════════════════════════════════════════════════╝\n");

        // Initialize enclave provisioner (async)
        let provisioner = Arc::new(EnclaveProvisioner::new().await?);

        println!("Enclave Pubkey: {}\n", hex::encode(provisioner.enclave_pubkey_bytes()));

        Ok(Self {
            provisioner,
            address_manager: Arc::new(tokio::sync::Mutex::new(None)),
        })
    }
}

// ============================================================================
// HTTP Handlers
// ============================================================================

/// Health check endpoint
pub async fn health_check() -> &'static str {
    "ok"
}

/// Get enclave status
#[derive(Serialize)]
pub struct StatusResponse {
    pub provisioned: bool,
    pub enclave_pubkey: String,
    pub version: String,
}

pub async fn get_status(State(state): State<EnclaveState>) -> Json<StatusResponse> {
    Json(StatusResponse {
        provisioned: state.provisioner.is_provisioned(),
        enclave_pubkey: hex::encode(state.provisioner.enclave_pubkey_bytes()),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

pub struct EnclaveState {
    pub provisioner: Arc<EnclaveProvisioner>,
    pub address_manager: Arc<tokio::sync::Mutex<Option<AddressManager>>>,
}

/// Provision the enclave with UFVK
pub async fn provision_ufvk(
    State(state): State<EnclaveState>,
    Json(req): Json<ProvisionRequest>,
) -> Result<Json<ProvisionResponse>, (StatusCode, String)> {
    info!("Received provisioning request");

    // 1. Provision the enclave
    let response = state.provisioner
        .provision(req)
        .await
        .map_err(|e| {
            error!("Provisioning failed: {}", e);
            (StatusCode::BAD_REQUEST, e.to_string())
        })?;

    // 2. Initialize AddressManager with UFVK
    let ufvk = state.provisioner
        .get_ufvk()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let manager = AddressManager::from_ufvk(&ufvk)
        .map_err(|e| {
            error!("Failed to initialize AddressManager: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;

    *state.address_manager.lock().await = Some(manager);

    info!("AddressManager initialized");
    info!("Enclave fully provisioned and ready");

    Ok(Json(response))
}

/// Request to generate a deposit address
#[derive(Debug, Deserialize)]
pub struct GenerateAddressRequest {
    pub solana_pubkey: String,
}

/// Response with generated address
#[derive(Debug, Serialize)]
pub struct GenerateAddressResponse {
    pub unified_address: String,
    pub diversifier_index: u32,
    pub solana_pubkey: String,
}

/// Generate a deposit address for a user
pub async fn generate_deposit_address(
    State(state): State<EnclaveState>,
    Json(req): Json<GenerateAddressRequest>,
) -> Result<Json<GenerateAddressResponse>, (StatusCode, String)> {
    // 1. Check if provisioned
    if !state.provisioner.is_provisioned() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Enclave not provisioned. Call /provision first.".to_string()
        ));
    }

    // 2. Validate input
    if req.solana_pubkey.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "solana_pubkey cannot be empty".to_string()
        ));
    }

    // 3. Get AddressManager
    let manager_guard = state.address_manager.lock().await;
    let manager = manager_guard.as_ref()
        .ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "AddressManager not initialized".to_string()
        ))?;

    // 4. Generate address
    let (ua, div_index) = manager
        .generate_deposit_address(&req.solana_pubkey)
        .map_err(|e| {
            error!("Address generation failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;

    info!("Generated UA for {}: {}... (index {})",
        &req.solana_pubkey[..16.min(req.solana_pubkey.len())],
        &ua[..30.min(ua.len())],
        div_index
    );

    Ok(Json(GenerateAddressResponse {
        unified_address: ua,
        diversifier_index: div_index,
        solana_pubkey: req.solana_pubkey,
    }))
}