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
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, error};



// use crate::provisioning::{EnclaveProvisioner, ProvisionRequest, ProvisionResponse};

use crate::manager::{AddressManager, EnclaveProvisioner, ProvisionRequest, ProvisionResponse};


/// Shared state across all handlers
#[derive(Clone)]
pub struct EnclaveStateClient {
    provisioner: Arc<EnclaveProvisioner>,
    address_manager: Arc<tokio::sync::Mutex<Option<AddressManager>>>,
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
    println!("║     🔐 Zcash Enclave Service Starting...          ║");
    println!("╚════════════════════════════════════════════════════╝\n");
    
    // Initialize enclave provisioner
    let provisioner = Arc::new(EnclaveProvisioner::new());
    
    println!("📍 Enclave Pubkey: {}\n", hex::encode(provisioner.enclave_pubkey().as_bytes()));
    
    // Create shared state
    let state = EnclaveStateClient {
        provisioner: provisioner.clone(),
        address_manager: Arc::new(tokio::sync::Mutex::new(None)),
    };
    Ok(
    Self{
        provisioner: state.provisioner,
        address_manager: state.address_manager,
    }
    )
}
    }

// #[tokio::main]
// async fn main() -> Result<()> {

    
//     // Build router
//     let app = Router::new()
//         .route("/health", get(health_check))
//         .route("/status", get(get_status))
//         .route("/provision", post(provision_ufvk))
//         .route("/generate-address", post(generate_deposit_address))
//         .with_state(state);
    
//     // Start server
//     let listener = tokio::net::TcpListener::bind("0.0.0.0:8443").await?;
    
//     println!("✅ Enclave API listening on :8443");
//     println!("📍 Endpoints:");
//     println!("   GET  /health              - Health check");
//     println!("   GET  /status              - Provisioning status");
//     println!("   POST /provision           - Provision UFVK from MPC");
//     println!("   POST /generate-address    - Generate deposit UA");
//     println!("\n⏳ Waiting for UFVK provisioning from MPC...\n");
    
//     axum::serve(listener, app).await?;
    
//     Ok(())
// }


// ============================================================================
// HTTP Handlers
// ============================================================================

/// Health check endpoint
async fn health_check() -> &'static str {
    "ok"
}

/// Get enclave status
#[derive(Serialize)]
struct StatusResponse {
    provisioned: bool,
    enclave_pubkey: String,
    version: String,
}

async fn get_status(State(state): State<EnclaveState>) -> Json<StatusResponse> {
    Json(StatusResponse {
        provisioned: state.provisioner.is_provisioned(),
        enclave_pubkey: hex::encode(state.provisioner.enclave_pubkey().as_bytes()),
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
    info!("📥 Received provisioning request");
    
    // 1. Provision the enclave
    let response = state.provisioner
        .provision(req)
        .map_err(|e| {
            error!("❌ Provisioning failed: {}", e);
            (StatusCode::BAD_REQUEST, e.to_string())
        })?;
    
    // 2. Initialize AddressManager with UFVK
    let ufvk = state.provisioner
        .get_ufvk()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let manager = AddressManager::from_ufvk(&ufvk)
        .map_err(|e| {
            error!("❌ Failed to initialize AddressManager: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;
    
    *state.address_manager.lock().await = Some(manager);
    
    info!("✅ AddressManager initialized");
    info!("✅ Enclave fully provisioned and ready");
    
    Ok(Json(response))
}

/// Request to generate a deposit address
#[derive(Debug, Deserialize)]
struct GenerateAddressRequest {
    solana_pubkey: String,
}

/// Response with generated address
#[derive(Debug, Serialize)]
struct GenerateAddressResponse {
    unified_address: String,
    diversifier_index: u32,
    solana_pubkey: String,
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
            error!("❌ Address generation failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;
    
    info!("✅ Generated UA for {}: {}... (index {})", 
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