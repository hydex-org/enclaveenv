//! ZCash RPC Client Service
//! 
//! Connects scanning, address management, and attestation generation.

use actix_web::http::header::HeaderMap;
use anyhow::{bail, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use zcash_address::{unified, Network};
use zcash_address::unified::{Container, Encoding};
use crate::client::wallet::{BlockId, CompactBlock};
use crate::client::{EnclaveStateClient, LightwalletdClient};
use crate::manager::{AddressManager, DepositAttestation, EnclaveProvisioner, ProvisionRequest};
use crate::scanner::{DecryptedNote, OrchardScanner};

// ============================================================================
// TYPES
// ============================================================================

/// Detected deposit ready for attestation
#[derive(Debug, Clone)]
pub struct DetectedDeposit {
    pub note: DecryptedNote,
    pub block_height: u64,
    pub solana_pubkey: [u8; 32],
    pub diversifier_index: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DepositAddressResponse {
    pub deposit_address: String,
    pub diversifier_index: u32,
    pub solana_pubkey: String,
    pub network: String,
    pub ufvk: String,
    pub note: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub challenge: String,
    pub nonce: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct DepositAddressRequest {
    solana_pubkey: String,
}

// ============================================================================
// CLI ARGS
// ============================================================================

#[derive(Parser)]
#[command(name = "zcash-enclave")]
#[command(about = "Zcash Enclave - Scan and attest deposits", long_about = None)]
struct Cli {
    /// Unified Full Viewing Key
    #[arg(short, long, default_value = "")]
    ufvk: String,

    /// Lightwalletd server URL
    #[arg(short, long, default_value = "https://testnet.zec.rocks:443")]
    server: String,

    /// Network (testnet or mainnet)
    #[arg(short, long, default_value = "testnet")]
    network: String,

    /// Number of blocks to scan (default: 10000)
    #[arg(short, long, default_value = "10000")]
    blocks: u64,

    /// Bridge address for context
    #[arg(short, long)]
    address: Option<String>,
}

// ============================================================================
// SERVICE
// ============================================================================

pub struct ZCashRpcClientService {
    pub read_only_rpc_client: LightwalletdClient,
    pub orchard_scanner: Option<OrchardScanner>,
    pub address_manager: Option<AddressManager>,
    pub enclave_state_client: EnclaveStateClient,
    pub enclave_provisioner: EnclaveProvisioner,
    
    /// Queue of pending attestations to submit to Solana
    pub pending_attestations: Arc<Mutex<VecDeque<DepositAttestation>>>,
    
    /// Last scanned block height
    pub last_scanned_height: u64,
    
    /// Network
    pub network: Network,
}

impl ZCashRpcClientService {
    pub async fn new() -> Result<Self> {
        let cli = Cli::parse();

        println!("\n=========================================");
        println!("   Hydex Zcash Enclave Service");
        println!("=========================================\n");

        // Parse network
        let network = if cli.network == "mainnet" {
            Network::Main
        } else {
            Network::Test
        };

        println!("Network:     {:?}", network);
        println!("Server:      {}", cli.server);

        // Connect to lightwalletd
        println!("=== Connecting to Lightwalletd ===");
        let read_only_rpc_client = match LightwalletdClient::connect(cli.server.clone()).await {
            Ok(c) => {
                println!("Connected to {}", cli.server);
                c
            }
            Err(e) => {
                println!("Failed to connect: {}", e);
                return Err(e);
            }
        };

        // Create enclave provisioner (always created - handles Ed25519 keypair)
        let enclave_provisioner = EnclaveProvisioner::new();
        println!("Enclave pubkey: {}", hex::encode(enclave_provisioner.enclave_pubkey_bytes()));

        // Check if UFVK was provided at startup
        let (orchard_scanner, address_manager) = if !cli.ufvk.is_empty() {
            println!("\n=== Decoding UFVK ===");
            match Self::init_with_ufvk(&cli.ufvk, network, &enclave_provisioner) {
                Ok((scanner, manager)) => {
                    println!("Scanner and address manager initialized");
                    (Some(scanner), Some(manager))
                }
                Err(e) => {
                    println!("Failed to initialize with UFVK: {}", e);
                    (None, None)
                }
            }
        } else {
            println!("\n=== No UFVK provided ===");
            println!("Enclave starting in UNPROVISIONED mode.");
            println!("Call POST /v1/provision with UFVK from MPC nodes to enable scanning.");
            (None, None)
        };

        let enclave_state_client = EnclaveStateClient::new().await?;

        println!("\nEnclave ready! (provisioned: {})\n", orchard_scanner.is_some());

        Ok(Self {
            read_only_rpc_client,
            orchard_scanner,
            address_manager,
            enclave_state_client,
            enclave_provisioner,
            pending_attestations: Arc::new(Mutex::new(VecDeque::new())),
            last_scanned_height: 0,
            network,
        })
    }

    /// Initialize scanner and address manager from UFVK
    fn init_with_ufvk(
        ufvk_str: &str,
        network: Network,
        provisioner: &EnclaveProvisioner,
    ) -> Result<(OrchardScanner, AddressManager)> {
        let decoded = unified::Ufvk::decode(ufvk_str)
            .map_err(|e| anyhow::anyhow!("Invalid UFVK: {:?}", e))?;

        let (parsed_net, ufvk) = decoded;
        if parsed_net != network {
            anyhow::bail!("Network mismatch: UFVK is for {:?} but running on {:?}", parsed_net, network);
        }

        // Extract Orchard FVK
        let mut orchard_fvk_bytes: Option<[u8; 96]> = None;
        for item in ufvk.items() {
            if let unified::Fvk::Orchard(bytes) = item {
                if bytes.len() == 96 {
                    let mut arr = [0u8; 96];
                    arr.copy_from_slice(&bytes);
                    orchard_fvk_bytes = Some(arr);
                    break;
                }
            }
        }

        let fvk_bytes = orchard_fvk_bytes
            .ok_or_else(|| anyhow::anyhow!("No Orchard FVK in UFVK"))?;

        let scanner = OrchardScanner::new(&fvk_bytes)?;
        let manager = AddressManager::from_ufvk(ufvk_str)?;

        // Auto-provision
        let provision_req = ProvisionRequest {
            ufvk: ufvk_str.to_string(),
            bridge_ua: String::new(),
            admin_signature: "auto".to_string(),
        };
        let _ = provisioner.provision(provision_req);

        Ok((scanner, manager))
    }

    // ========================================================================
    // SCANNING
    // ========================================================================

    /// Scan a single block for deposits
    /// Returns detected deposits with their attestations
    pub async fn scan_block(&mut self, height: u64) -> Result<Vec<DepositAttestation>> {
        let req = BlockId {
            height,
            hash: vec![],
        };

        let block = self.read_only_rpc_client.get_block(req).await?.into_inner();
        let mut attestations = Vec::new();

        for tx in &block.vtx {
            for action in &tx.actions {
                // Try to decrypt - need as_mut() because try_decrypt_action takes &mut self
                if let Some(note) = self.orchard_scanner.as_mut().unwrap().try_decrypt_action(
                    &action.nullifier,
                    &action.cmx,
                    &action.ephemeral_key,
                    &action.ciphertext,
                    self.network,
                ) {
                    println!("  Found deposit: {} zatoshi at block {}", note.value, height);

                    // Look up Solana pubkey from address - call self method, not AddressManager
                    if let Some((solana_pubkey_str, _div_index)) = 
                        self.find_solana_pubkey_for_address(&note.recipient_address) 
                    {
                        // Convert solana pubkey string to bytes
                        let solana_pubkey = Self::parse_solana_pubkey(&solana_pubkey_str)?;

                        // Generate attestation
                        let attestation = self.enclave_provisioner.sign_attestation(
                            note.note_commitment,
                            note.value,
                            solana_pubkey,
                            height,
                        )?;

                        println!("    Attestation signed for Solana user: {}...", 
                            &solana_pubkey_str[..16.min(solana_pubkey_str.len())]);

                        // Queue for submission
                        {
                            let mut queue = self.pending_attestations.lock().unwrap();
                            queue.push_back(attestation.clone());
                        }

                        attestations.push(attestation);
                    } else {
                        println!("    Warning: No Solana mapping for address {}", 
                            &note.recipient_address[..30.min(note.recipient_address.len())]);
                    }
                }
            }
        }

        self.last_scanned_height = height;
        Ok(attestations)
    }

    /// Scan a range of blocks
    pub async fn scan_blocks(&mut self, start_height: u64, end_height: u64) -> Result<Vec<DepositAttestation>> {
        let mut all_attestations = Vec::new();

        println!("Scanning blocks {} to {}...", start_height, end_height);

        for height in start_height..=end_height {
            if height % 100 == 0 {
                println!("  Scanning block {}...", height);
            }

            match self.scan_block(height).await {
                Ok(attestations) => {
                    all_attestations.extend(attestations);
                }
                Err(e) => {
                    println!("  Error scanning block {}: {}", height, e);
                }
            }
        }

        println!("Scan complete. Found {} deposits.", all_attestations.len());
        Ok(all_attestations)
    }

    /// Get pending attestations (for submission to Solana)
    pub fn get_pending_attestations(&self) -> Vec<DepositAttestation> {
        let queue = self.pending_attestations.lock().unwrap();
        queue.iter().cloned().collect()
    }

    /// Remove an attestation from the queue (after successful submission)
    pub fn mark_attestation_submitted(&self, note_commitment: &[u8; 32]) {
        let mut queue = self.pending_attestations.lock().unwrap();
        queue.retain(|a| &a.note_commitment != note_commitment);
    }

    // ========================================================================
    // PROVISIONING (called after MPC nodes provision the enclave)
    // ========================================================================

    /// Initialize scanner and address manager after API provisioning
    /// 
    /// This is called by the controller after a successful /v1/provision request.
    /// It sets up the orchard_scanner and address_manager using the provisioned UFVK.
    pub fn init_after_provisioning(&mut self) -> Result<()> {
        // Get the UFVK from the provisioner
        let ufvk_str = self.enclave_provisioner.get_ufvk()?;
        
        // Initialize using the shared helper
        let (scanner, manager) = Self::init_with_ufvk(&ufvk_str, self.network, &self.enclave_provisioner)?;
        
        self.orchard_scanner = Some(scanner);
        self.address_manager = Some(manager);
        
        println!("=== Enclave Provisioned via API ===");
        println!("Scanner and address manager now active");
        
        Ok(())
    }

    /// Check if the enclave is ready for operations
    pub fn is_ready(&self) -> bool {
        self.enclave_provisioner.is_provisioned() 
            && self.orchard_scanner.is_some() 
            && self.address_manager.is_some()
    }

    // ========================================================================
    // ADDRESS MANAGEMENT
    // ========================================================================

    /// Generate a deposit address for a Solana user
    pub async fn generate_deposit_address(&self, solana_pubkey: &str) -> Result<DepositAddressResponse> {
       let req = DepositAddressRequest {
            solana_pubkey: solana_pubkey.to_string(),
        };
        let client = reqwest::Client::new();
        let resp = client
            .post("http://localhost:3001/api/deposit-address")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&req)
            .send()
            .await?;
        let parsed: DepositAddressResponse = resp.json().await?;
        Ok(parsed)
    }

    /// Find Solana pubkey for a Zcash address (reverse lookup)
    fn find_solana_pubkey_for_address(&self, zcash_address: &str) -> Option<(String, u32)> {
        let manager = self.address_manager.as_ref()?;
        let mappings = manager.get_all_mappings();
        for (solana_pk, (div_index, ua)) in mappings {
            if ua == zcash_address {
                return Some((solana_pk, div_index));
            }
        }
        None
    }

    /// Parse Solana pubkey from string to bytes
    fn parse_solana_pubkey(pubkey_str: &str) -> Result<[u8; 32]> {
        // Try base58 decode first (standard Solana format)
        if let Ok(bytes) = bs58::decode(pubkey_str).into_vec() {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return Ok(arr);
            }
        }
        
        // Try hex decode
        if let Ok(bytes) = hex::decode(pubkey_str) {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return Ok(arr);
            }
        }

        bail!("Invalid Solana pubkey format: {}", pubkey_str)
    }

    // ========================================================================
    // LEGACY METHODS (kept for compatibility)
    // ========================================================================

    pub async fn emit_orchard(&mut self, _data: Vec<u8>, height: u64) -> Result<CompactBlock> {
        let req = BlockId {
            height,
            hash: vec![],
        };

        let block = self.read_only_rpc_client.get_block(req).await?.into_inner();

        for tx in &block.vtx {
            for action in &tx.actions {
                // Fix: as_mut() instead of as_ref()
                if let Some(note) = self.orchard_scanner.as_mut().unwrap().try_decrypt_action(
                    &action.nullifier,
                    &action.cmx,
                    &action.ephemeral_key,
                    &action.ciphertext,
                    self.network,
                ) {
                    println!("  Found note: {:?}", note);
                }
            }
        }
        Ok(block)
    }

    pub async fn connect_wallet(&mut self, wallet: String) -> Result<DepositAddressResponse> {
        let client = reqwest::Client::new();
        let req = DepositAddressRequest {
            solana_pubkey: wallet,
        };
        let resp = client
            .post("http://localhost:3001/api/deposit-address")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&req)
            .send()
            .await?;
        let parsed: DepositAddressResponse = resp.json().await?;
        Ok(parsed)
    }

    pub async fn auth_challenge(
        &mut self,
        wallet: String,
        _deposit_address: String,
    ) -> Result<DepositAddressResponse> {
        let client = reqwest::Client::new();
        let req = DepositAddressRequest {
            solana_pubkey: wallet,
        };
        let resp = client
            .get("http://localhost:8080/bridge-address")
            .json(&req)
            .send()
            .await?;
        let parsed: DepositAddressResponse = resp.json().await?;
        Ok(parsed)
    }
}