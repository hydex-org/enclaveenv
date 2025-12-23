//! ZCash RPC Client Service
//! 
//! Connects scanning, address management, attestation generation, and Solana minting.

use anyhow::{bail, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zcash_address::{unified, Network};
use zcash_address::unified::{Container, Encoding};
use crate::client::wallet::{BlockId, CompactBlock};
use crate::client::{EnclaveStateClient, LightwalletdClient};
use crate::manager::{AddressManager, DepositAttestation, EnclaveProvisioner};
use crate::scanner::{DecryptedNote, OrchardScanner};
use crate::service::mint_client::{EnclaveSolanaClient, MintResult};

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

#[derive(Debug, Deserialize, Serialize)]
struct DepositAddressRequest {
    solana_pubkey: String,
}

/// Result of processing a detected deposit
#[derive(Debug, Clone)]
pub struct ProcessedDeposit {
    pub attestation: DepositAttestation,
    pub mint_result: Option<MintResult>,
    pub error: Option<String>,
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

    /// Solana RPC URL
    #[arg(long, default_value = "https://api.devnet.solana.com")]
    solana_rpc: String,

    /// Solana program ID (wzec_bridge)
    #[arg(long, default_value = "")]
    program_id: String,
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
    
    /// Solana client for direct mint submission
    pub solana_client: Option<EnclaveSolanaClient>,
    
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
        let enclave_provisioner = EnclaveProvisioner::new().await?;
        println!("Enclave pubkey: {}", hex::encode(enclave_provisioner.enclave_pubkey_bytes()));

        // Initialize Solana client if program ID is provided
        let solana_client = if !cli.program_id.is_empty() {
            println!("\n=== Initializing Solana Client ===");
            match EnclaveSolanaClient::new(&cli.solana_rpc, &cli.program_id).await {
                Ok(client) => {
                    println!("Solana client ready");
                    Some(client)
                }
                Err(e) => {
                    println!("Warning: Failed to initialize Solana client: {}", e);
                    println!("Minting will be disabled until Solana client is configured.");
                    None
                }
            }
        } else {
            println!("\n=== Solana Client Not Configured ===");
            println!("Set --program-id to enable direct minting.");
            None
        };

        // Check if UFVK was provided at startup
        let (orchard_scanner, address_manager) = if !cli.ufvk.is_empty() {
            println!("\n=== Decoding UFVK ===");
            match Self::init_with_ufvk(&cli.ufvk, network, &enclave_provisioner).await {
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

        println!("\nEnclave ready!");
        println!("   Provisioned: {}", orchard_scanner.is_some());
        println!("   Solana mint: {}\n", solana_client.is_some());

        Ok(Self {
            read_only_rpc_client,
            orchard_scanner,
            address_manager,
            enclave_state_client,
            enclave_provisioner,
            solana_client,
            last_scanned_height: 0,
            network,
        })
    }

    /// Initialize scanner and address manager from UFVK
    async fn init_with_ufvk(
        ufvk_str: &str,
        network: Network,
        _provisioner: &EnclaveProvisioner,
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
        let manager = AddressManager::from_ufvk(ufvk_str).await?;

        // Load persisted mappings from disk
        match manager.load_mappings() {
            Ok(count) => {
                if count > 0 {
                    println!("Restored {} address mappings from disk", count);
                }
            }
            Err(e) => {
                println!("Warning: Could not load persisted mappings: {}", e);
            }
        }

        tracing::info!("Scanner and address manager initialized from startup UFVK");

        Ok((scanner, manager))
    }

    // ========================================================================
    // SCANNING + DIRECT MINTING
    // ========================================================================

    /// Scan a single block for deposits and submit mints directly
    pub async fn scan_block(&mut self, height: u64) -> Result<Vec<ProcessedDeposit>> {
        let req = BlockId {
            height,
            hash: vec![],
        };

        let block = self.read_only_rpc_client.get_block(req).await?.into_inner();
        let mut processed = Vec::new();

        for tx in &block.vtx {
            for action in &tx.actions {
                // Try to decrypt
                if let Some(note) = self.orchard_scanner.as_mut().unwrap().try_decrypt_action(
                    &action.nullifier,
                    &action.cmx,
                    &action.ephemeral_key,
                    &action.ciphertext,
                    self.network,
                ) {
                    println!("  Found deposit: {} zatoshi at block {}", note.value, height);

                    // Look up Solana pubkey from address
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

                        // Submit mint directly to Solana
                        let mint_result = if let Some(ref solana_client) = self.solana_client {
                            let user_pubkey = solana_sdk::pubkey::Pubkey::new_from_array(solana_pubkey);
                            
                            match solana_client.submit_mint(&attestation, &user_pubkey).await {
                                Ok(result) => {
                                    if result.success {
                                        println!("    MINTED! TX: {}", result.signature);
                                    } else {
                                        println!("    Mint skipped: {}", result.signature);
                                    }
                                    Some(result)
                                }
                                Err(e) => {
                                    println!("    Mint failed: {}", e);
                                    processed.push(ProcessedDeposit {
                                        attestation: attestation.clone(),
                                        mint_result: None,
                                        error: Some(e.to_string()),
                                    });
                                    continue;
                                }
                            }
                        } else {
                            println!("    Warning: Solana client not configured, attestation not submitted");
                            None
                        };

                        processed.push(ProcessedDeposit {
                            attestation,
                            mint_result,
                            error: None,
                        });
                    } else {
                        println!("    Warning: No Solana mapping for address {}", 
                            &note.recipient_address[..30.min(note.recipient_address.len())]);
                    }
                }
            }
        }

        self.last_scanned_height = height;
        Ok(processed)
    }

    /// Scan a range of blocks
    pub async fn scan_blocks(&mut self, start_height: u64, end_height: u64) -> Result<Vec<ProcessedDeposit>> {
        let mut all_processed = Vec::new();

        println!("Scanning blocks {} to {}...", start_height, end_height);

        for height in start_height..=end_height {
            if height % 100 == 0 {
                println!("  Scanning block {}...", height);
            }

            match self.scan_block(height).await {
                Ok(deposits) => {
                    all_processed.extend(deposits);
                }
                Err(e) => {
                    println!("  Error scanning block {}: {}", height, e);
                }
            }
        }

        let minted_count = all_processed.iter().filter(|p| p.mint_result.is_some()).count();
        println!("Scan complete. Found {} deposits, {} minted.", all_processed.len(), minted_count);
        Ok(all_processed)
    }

    // ========================================================================
    // PROVISIONING
    // ========================================================================

    /// Initialize scanner and address manager after API provisioning
    pub async fn init_after_provisioning(&mut self) -> Result<()> {
        let ufvk_str = self.enclave_provisioner.get_ufvk()?;
        let (scanner, manager) = Self::init_with_ufvk(&ufvk_str, self.network, &self.enclave_provisioner).await?;
        
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

    /// Check if minting is enabled
    pub fn can_mint(&self) -> bool {
        self.is_ready() && self.solana_client.is_some()
    }

    // ========================================================================
    // ADDRESS MANAGEMENT
    // ========================================================================

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
        if self.address_manager.is_none() {
            anyhow::bail!("Enclave not provisioned. MPC nodes must call /v1/provision first.");
        }

        let address_manager = self.address_manager.as_ref().unwrap();
        
        let (unified_address, diversifier_index) = address_manager
            .generate_deposit_address(&wallet).await
            .map_err(|e| anyhow::anyhow!("Failed to generate address: {}", e))?;

if let Some(ref am) = self.address_manager {
    if let Err(e) = am.save_mappings().await {
        eprintln!("Warning: Failed to save address mappings: {}", e);
    }
}

        Ok(DepositAddressResponse {
            deposit_address: unified_address.clone(),
            diversifier_index,
            solana_pubkey: wallet,
            network: "testnet".to_string(),
            ufvk: unified_address,
            note: "Send ZEC to this address to receive sZEC on Solana".to_string(),
        })
    }
}