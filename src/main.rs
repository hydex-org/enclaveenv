use actix_web::{App, HttpServer, http, web};
use actix_cors::Cors;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

mod controller;
mod service;
mod client;
mod scanner;
mod manager;

use crate::controller::ZCashController;

/// Background scanner configuration
struct ScannerConfig {
    /// How often to check for new blocks (seconds)
    poll_interval_secs: u64,
    /// Minimum confirmations before processing a deposit
    min_confirmations: u64,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: 30,  // Check every 30 seconds
            min_confirmations: 10,   // Wait for 10 confirmations
        }
    }
}

/// Run the continuous background scanner
async fn run_background_scanner(controller: Arc<ZCashController>, config: ScannerConfig) {
    println!("\n=== Background Scanner Started ===");
    println!("   Poll interval: {}s", config.poll_interval_secs);
    println!("   Min confirmations: {}", config.min_confirmations);
    println!("   Waiting for enclave to be provisioned...\n");
    
    let poll_interval = Duration::from_secs(config.poll_interval_secs);
    
    loop {
        // Check if provisioned
        let is_ready = {
            let service = controller.zcash_service.lock().await;
            service.is_ready()
        };
        
        if !is_ready {
            // Not provisioned yet, wait and retry
            sleep(Duration::from_secs(5)).await;
            continue;
        }
        
        // Get chain tip
        let chain_tip = {
            let mut service = controller.zcash_service.lock().await;
            match service.read_only_rpc_client.get_latest_block().await {
                Ok(tip) => tip,
                Err(e) => {
                    eprintln!("[Scanner] Failed to get chain tip: {}", e);
                    sleep(poll_interval).await;
                    continue;
                }
            }
        };
        
        // Calculate safe scan range (with confirmations)
        let safe_tip = chain_tip.saturating_sub(config.min_confirmations);
        
        // Get last scanned height
        let last_scanned = {
            let service = controller.zcash_service.lock().await;
            service.last_scanned_height
        };
        
        // If we haven't scanned anything yet, start from recent blocks
        let start_height = if last_scanned == 0 {
            // Start from 1000 blocks before safe tip (or 0 if chain is shorter)
            safe_tip.saturating_sub(1000)
        } else {
            last_scanned + 1
        };
        
        // Check if there are new blocks to scan
        if start_height > safe_tip {
            // Already caught up, wait for new blocks
            sleep(poll_interval).await;
            continue;
        }
        
        // Scan in batches of 100 blocks
        let batch_size = 100u64;
        let end_height = std::cmp::min(start_height + batch_size - 1, safe_tip);
        
        println!("[Scanner] Scanning blocks {} to {} (tip: {}, safe: {})", 
            start_height, end_height, chain_tip, safe_tip);
        
        // Perform the scan
        let scan_result = {
            let mut service = controller.zcash_service.lock().await;
            service.scan_blocks(start_height, end_height).await
        };
        
        match scan_result {
            Ok(attestations) => {
                if !attestations.is_empty() {
                    println!("[Scanner] Found {} deposits!", attestations.len());
                    for att in &attestations {
                        println!("   - {} zatoshi at block {}", att.amount, att.block_height);
                    }
                }
            }
            Err(e) => {
                eprintln!("[Scanner] Scan error: {}", e);
            }
        }
        
        // Brief pause between batches if more to scan, otherwise wait for poll interval
        if end_height < safe_tip {
            sleep(Duration::from_millis(100)).await;
        } else {
            sleep(poll_interval).await;
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting Zcash Enclave server...");

    let zcash_controller = Arc::new(ZCashController::new().await.unwrap());

    // Start background scanner
    let scanner_controller = zcash_controller.clone();
    tokio::spawn(async move {
        run_background_scanner(scanner_controller, ScannerConfig::default()).await;
    });

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