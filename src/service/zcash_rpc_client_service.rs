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
    pub orchard_scanner: OrchardScanner,
    pub address_manager: AddressManager,
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
        println!("Scan depth:  {} blocks\n", cli.blocks);

        // Connect to lightwalletd
        println!("=== Connecting to Lightwalletd ===");
        let read_only_rpc_client = match LightwalletdClient::connect(cli.server.clone()).await {
            Ok(c) => {
                println!("Connected to {}", cli.server);
                c
            }
            Err(e) => {
                println!("Failed to connect: {}", e);
                println!("Try: --server https://lightwalletd.testnet.electriccoin.co:9067");
                return Err(e);
            }
        };

        // Decode UFVK
        println!("\n=== Decoding UFVK ===");
        let decoded = match unified::Ufvk::decode(&cli.ufvk) {
            Ok((parsed_net, ufvk)) => {
                if parsed_net != network {
                    bail!("Network mismatch: UFVK is for {:?} but running on {:?}", parsed_net, network);
                }
                println!("UFVK valid for {:?}", parsed_net);
                ufvk
            }
            Err(e) => bail!("Invalid UFVK: {:?}", e),
        };

        // Extract Orchard FVK
        let mut orchard_fvk_bytes: Option<[u8; 96]> = None;
        for item in decoded.items() {
            if let unified::Fvk::Orchard(bytes) = item {
                if bytes.len() == 96 {
                    let mut arr = [0u8; 96];
                    arr.copy_from_slice(&bytes);
                    orchard_fvk_bytes = Some(arr);
                    println!("Orchard FVK extracted (96 bytes)");
                    break;
                }
            }
        }

        let fvk_bytes = orchard_fvk_bytes
            .ok_or_else(|| anyhow::anyhow!("No Orchard FVK in UFVK"))?;

        // Initialize components
        let orchard_scanner = OrchardScanner::new(&fvk_bytes)?;
        println!("Scanner initialized");

        let address_manager = AddressManager::from_ufvk(&cli.ufvk)?;
        println!("Address manager initialized");

        let enclave_state_client = EnclaveStateClient::new().await?;

        let enclave_provisioner = EnclaveProvisioner::new();
        println!("Enclave pubkey: {}", hex::encode(enclave_provisioner.enclave_pubkey_bytes()));

        // Auto-provision with the UFVK
        let provision_req = ProvisionRequest {
            ufvk: cli.ufvk.clone(),
            bridge_ua: cli.address.unwrap_or_default(),
            admin_signature: "auto".to_string(),
        };
        match enclave_provisioner.provision(provision_req) {
            Ok(_) => println!("Enclave auto-provisioned with UFVK"),
            Err(e) => println!("Provision note: {}", e),
        }

        println!("\nEnclave ready!\n");

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
                // Try to decrypt
                if let Some(note) = self.orchard_scanner.try_decrypt_action(
                    &action.nullifier,
                    &action.cmx,
                    &action.ephemeral_key,
                    &action.ciphertext,
                    self.network,
                ) {
                    println!("  Found deposit: {} zatoshi at block {}", note.value, height);

                    // Look up Solana pubkey from address
                    // For now, we need to reverse-lookup from the address
                    // In production, you'd have a mapping from UA -> solana_pubkey
                    if let Some((solana_pubkey_str, div_index)) = 
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
    // ADDRESS MANAGEMENT
    // ========================================================================

    /// Generate a deposit address for a Solana user
    pub fn generate_deposit_address(&self, solana_pubkey: &str) -> Result<(String, u32)> {
        self.address_manager.generate_deposit_address(solana_pubkey)
    }

    /// Find Solana pubkey for a Zcash address (reverse lookup)
    fn find_solana_pubkey_for_address(&self, zcash_address: &str) -> Option<(String, u32)> {
        let mappings = self.address_manager.get_all_mappings();
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
                if let Some(note) = self.orchard_scanner.try_decrypt_action(
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