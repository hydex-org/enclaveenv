//! Enclave Solana Client for Direct Minting
//!
//! Priority: Environment variables > File storage

use anyhow::{Context, Result};
use base64::Engine;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    transaction::Transaction,
};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use crate::manager::DepositAttestation;

const DATA_DIR: &str = "data/enclave";
const SOLANA_KEYPAIR_FILE: &str = "solana-keypair.json";

// Environment variable name
const ENV_SOLANA_KEYPAIR: &str = "ENCLAVE_SOLANA_KEYPAIR";  // JSON array of 64 bytes

/// System Program ID - all zeros (11111111111111111111111111111111 in base58)
fn system_program_id() -> Pubkey {
    Pubkey::new_from_array([0u8; 32])
}

/// Token Program ID
fn token_program_id() -> Pubkey {
    Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap()
}

/// Associated Token Program ID
fn ata_program_id() -> Pubkey {
    Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap()
}

/// Solana client for enclave minting operations
pub struct EnclaveSolanaClient {
    client: Client,
    rpc_url: String,
    program_id: Pubkey,
    payer: Arc<Keypair>,
}

/// Result of a mint operation
#[derive(Debug, Clone)]
pub struct MintResult {
    pub signature: String,
    pub deposit_id: u64,
    pub success: bool,
}

// ============================================================================
// JSON-RPC TYPES
// ============================================================================

#[derive(Serialize)]
struct RpcRequest<T: Serialize> {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: T,
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize, Debug)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct GetLatestBlockhashResult {
    value: BlockhashValue,
}

#[derive(Deserialize)]
struct BlockhashValue {
    blockhash: String,
}

#[derive(Deserialize)]
struct GetAccountInfoResult {
    value: Option<AccountValue>,
}

#[derive(Deserialize)]
struct AccountValue {
    data: Vec<String>,
    #[allow(dead_code)]
    lamports: u64,
}

// ============================================================================
// IMPLEMENTATION
// ============================================================================

impl EnclaveSolanaClient {
    /// Create a new Solana client
    pub async fn new(rpc_url: &str, program_id: &str) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        let program_id = Pubkey::from_str(program_id)
            .context("Invalid program ID")?;

        let data_dir = PathBuf::from(DATA_DIR);
        std::fs::create_dir_all(&data_dir)?;

        let payer = Self::load_or_generate_keypair(&data_dir)?;

        tracing::info!("Enclave Solana client initialized");
        tracing::info!("   RPC: {}", rpc_url);
        tracing::info!("   Program: {}", program_id);
        tracing::info!("   Payer: {}", payer.pubkey());

        Ok(Self {
            client,
            rpc_url: rpc_url.to_string(),
            program_id,
            payer: Arc::new(payer),
        })
    }

    fn load_or_generate_keypair(data_dir: &PathBuf) -> Result<Keypair> {
        // 1. Try environment variable first (JSON array - can be 32 or 64 bytes)
        if let Ok(keypair_json) = std::env::var(ENV_SOLANA_KEYPAIR) {
            if let Ok(bytes) = serde_json::from_str::<Vec<u8>>(&keypair_json) {
                if bytes.len() >= 32 {
                    let mut secret = [0u8; 32];
                    secret.copy_from_slice(&bytes[..32]);
                    let keypair = Keypair::new_from_array(secret);
                    tracing::info!("Loaded Solana keypair from environment variable");
                    return Ok(keypair);
                }
            }
            tracing::warn!("Invalid {} format, trying file", ENV_SOLANA_KEYPAIR);
        }
    
        // 2. Try file (JSON array - can be 32 or 64 bytes)
        let keypair_path = data_dir.join(SOLANA_KEYPAIR_FILE);
        if keypair_path.exists() {
            if let Ok(contents) = std::fs::read_to_string(&keypair_path) {
                if let Ok(bytes) = serde_json::from_str::<Vec<u8>>(&contents) {
                    if bytes.len() >= 32 {
                        let mut secret = [0u8; 32];
                        secret.copy_from_slice(&bytes[..32]);
                        let keypair = Keypair::new_from_array(secret);
                        tracing::info!("Loaded Solana keypair from file");
                        return Ok(keypair);
                    }
                }
            }
            tracing::warn!("Existing keypair file is invalid, regenerating");
        }
    
        // 3. Generate new keypair
        let keypair = Keypair::new();
        // Store full 64 bytes for compatibility, but only first 32 are needed
        let keypair_json = serde_json::to_string(&keypair.to_bytes().to_vec())?;
        std::fs::write(&keypair_path, &keypair_json)?;
        tracing::info!("Generated and saved new Solana keypair: {}", keypair.pubkey());
        Ok(keypair)
    }

    pub fn payer_pubkey(&self) -> Pubkey {
        self.payer.pubkey()
    }

    // ========================================================================
    // PDA DERIVATION
    // ========================================================================

    fn derive_bridge_config_pda(&self) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"bridge-config"], &self.program_id)
    }

    fn derive_deposit_intent_pda(&self, user: &Pubkey, deposit_id: u64) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[b"deposit-intent", user.as_ref(), &deposit_id.to_le_bytes()],
            &self.program_id,
        )
    }

    fn derive_claim_tracker_pda(&self, note_commitment: &[u8; 32]) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[b"claim-tracker", note_commitment.as_ref()],
            &self.program_id,
        )
    }

    fn derive_szec_mint_pda(&self) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"szec-mint"], &self.program_id)
    }

    fn derive_mint_authority_pda(&self) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"mint-authority"], &self.program_id)
    }

    fn derive_associated_token_address(&self, owner: &Pubkey, mint: &Pubkey) -> Pubkey {
        let (address, _) = Pubkey::find_program_address(
            &[owner.as_ref(), token_program_id().as_ref(), mint.as_ref()],
            &ata_program_id(),
        );
        address
    }

    // ========================================================================
    // RPC HELPERS
    // ========================================================================

    async fn get_latest_blockhash(&self) -> Result<Hash> {
        let params = serde_json::json!([{"commitment": "confirmed"}]);

        let request = RpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "getLatestBlockhash",
            params,
        };

        let response: RpcResponse<GetLatestBlockhashResult> = self.client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await?
            .json()
            .await?;

        if let Some(error) = response.error {
            anyhow::bail!("RPC error: {} (code {})", error.message, error.code);
        }

        let blockhash_str = response.result
            .ok_or_else(|| anyhow::anyhow!("No blockhash in response"))?
            .value
            .blockhash;

        Hash::from_str(&blockhash_str).context("Invalid blockhash format")
    }

    async fn send_transaction(&self, transaction: &Transaction) -> Result<Signature> {
        let tx_bytes = bincode::serialize(transaction)?;
        let tx_base64 = base64::engine::general_purpose::STANDARD.encode(&tx_bytes);

        let params = serde_json::json!([
            tx_base64,
            {
                "encoding": "base64",
                "skipPreflight": false,
                "preflightCommitment": "confirmed"
            }
        ]);

        let request = RpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "sendTransaction",
            params,
        };

        let response: RpcResponse<String> = self.client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await?
            .json()
            .await?;

        if let Some(error) = response.error {
            anyhow::bail!("Transaction failed: {} (code {})", error.message, error.code);
        }

        let sig_str = response.result
            .ok_or_else(|| anyhow::anyhow!("No signature in response"))?;

        Signature::from_str(&sig_str).context("Invalid signature format")
    }

    async fn get_account_data(&self, pubkey: &Pubkey) -> Result<Option<Vec<u8>>> {
        let params = serde_json::json!([
            pubkey.to_string(),
            {"encoding": "base64", "commitment": "confirmed"}
        ]);

        let request = RpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "getAccountInfo",
            params,
        };

        let response: RpcResponse<GetAccountInfoResult> = self.client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await?
            .json()
            .await?;

        if let Some(error) = response.error {
            anyhow::bail!("RPC error: {} (code {})", error.message, error.code);
        }

        if let Some(result) = response.result {
            if let Some(account) = result.value {
                let data = base64::engine::general_purpose::STANDARD.decode(&account.data[0])?;
                return Ok(Some(data));
            }
        }

        Ok(None)
    }

    fn get_instruction_discriminator(name: &str) -> [u8; 8] {
        let preimage = format!("global:{}", name);
        let hash = Sha256::digest(preimage.as_bytes());
        let mut discriminator = [0u8; 8];
        discriminator.copy_from_slice(&hash[..8]);
        discriminator
    }

    // ========================================================================
    // ASSOCIATED TOKEN ACCOUNT MANAGEMENT
    // ========================================================================

    /// Create Associated Token Account if it doesn't exist
    async fn ensure_ata_exists(&self, owner: &Pubkey, mint: &Pubkey) -> Result<Pubkey> {
        let ata = self.derive_associated_token_address(owner, mint);
        
        // Check if ATA already exists
        if self.get_account_data(&ata).await?.is_some() {
            tracing::info!("ATA already exists: {}", ata);
            return Ok(ata);
        }
        
        tracing::info!("Creating ATA for {} (mint: {})", owner, mint);
        
        // Create ATA instruction (Associated Token Program)
        // Instruction data is empty for create
        let accounts = vec![
            AccountMeta::new(self.payer.pubkey(), true),      // funding account (payer)
            AccountMeta::new(ata, false),                      // associated token account to create
            AccountMeta::new_readonly(*owner, false),          // wallet address (owner)
            AccountMeta::new_readonly(*mint, false),           // token mint
            AccountMeta::new_readonly(system_program_id(), false),
            AccountMeta::new_readonly(token_program_id(), false),
        ];
        
        let instruction = Instruction {
            program_id: ata_program_id(),
            accounts,
            data: vec![], // Empty data = create instruction
        };
        
        let recent_blockhash = self.get_latest_blockhash().await?;
        let message = Message::new(&[instruction], Some(&self.payer.pubkey()));
        let mut transaction = Transaction::new_unsigned(message);
        transaction.sign(&[&*self.payer], recent_blockhash);
        
        let signature = self.send_transaction(&transaction).await?;
        tracing::info!("Created ATA: {} (tx: {})", ata, signature);
        
        Ok(ata)
    }

    // ========================================================================
    // DEPOSIT INTENT MANAGEMENT
    // ========================================================================

    async fn get_deposit_nonce(&self) -> Result<u64> {
        let (bridge_config_pda, _) = self.derive_bridge_config_pda();

        let data = self.get_account_data(&bridge_config_pda).await?
            .ok_or_else(|| anyhow::anyhow!("Bridge config not found"))?;

        if data.len() < 145 {
            anyhow::bail!("Bridge config account data too short");
        }

        let nonce_bytes: [u8; 8] = data[137..145].try_into()?;
        Ok(u64::from_le_bytes(nonce_bytes))
    }

    async fn deposit_intent_exists(&self, user: &Pubkey, deposit_id: u64) -> Result<bool> {
        let (pda, _) = self.derive_deposit_intent_pda(user, deposit_id);
        Ok(self.get_account_data(&pda).await?.is_some())
    }

    async fn is_note_claimed(&self, note_commitment: &[u8; 32]) -> Result<bool> {
        let (pda, _) = self.derive_claim_tracker_pda(note_commitment);
        Ok(self.get_account_data(&pda).await?.is_some())
    }

    pub async fn create_deposit_for_user(
        &self,
        recipient: &Pubkey,
        ua_hash: [u8; 32],
    ) -> Result<u64> {
        let deposit_nonce = self.get_deposit_nonce().await?;

        tracing::info!("Creating deposit intent for user {} (nonce: {})", recipient, deposit_nonce);

        let discriminator = Self::get_instruction_discriminator("create_deposit_for_user");

        let mut data = Vec::new();
        data.extend_from_slice(&discriminator);
        data.extend_from_slice(recipient.as_ref());
        data.extend_from_slice(&ua_hash);

        let (bridge_config_pda, _) = self.derive_bridge_config_pda();
        let (deposit_intent_pda, _) = self.derive_deposit_intent_pda(recipient, deposit_nonce);

        let accounts = vec![
            AccountMeta::new_readonly(self.payer.pubkey(), true),
            AccountMeta::new(self.payer.pubkey(), true),
            AccountMeta::new(bridge_config_pda, false),
            AccountMeta::new(deposit_intent_pda, false),
            AccountMeta::new_readonly(system_program_id(), false),
        ];

        let instruction = Instruction {
            program_id: self.program_id,
            accounts,
            data,
        };

        let recent_blockhash = self.get_latest_blockhash().await?;
        let message = Message::new(&[instruction], Some(&self.payer.pubkey()));
        let mut transaction = Transaction::new_unsigned(message);
        transaction.sign(&[&*self.payer], recent_blockhash);

        let signature = self.send_transaction(&transaction).await?;
        tracing::info!("Created deposit intent #{} (tx: {})", deposit_nonce, signature);

        Ok(deposit_nonce)
    }

    pub async fn ensure_deposit_intent(&self, user: &Pubkey) -> Result<u64> {
        let deposit_nonce = self.get_deposit_nonce().await?;

        for offset in 0..5u64 {
            let check_id = deposit_nonce.saturating_sub(offset);
            if self.deposit_intent_exists(user, check_id).await? {
                tracing::info!("Found existing deposit intent #{} for {}", check_id, user);
                return Ok(check_id);
            }
        }

        let mut ua_hash = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(user.as_ref());
        hasher.update(&deposit_nonce.to_le_bytes());
        hasher.update(b"hydex-ua-hash");
        ua_hash.copy_from_slice(&hasher.finalize()[..32]);

        self.create_deposit_for_user(user, ua_hash).await
    }

    // ========================================================================
    // MINTING
    // ========================================================================

    pub async fn submit_mint(
        &self,
        attestation: &DepositAttestation,
        user: &Pubkey,
    ) -> Result<MintResult> {
        tracing::info!(
            "Submitting mint for user {} (amount: {} zatoshi)",
            user,
            attestation.amount
        );

        let deposit_id = self.ensure_deposit_intent(user).await?;

        if self.is_note_claimed(&attestation.note_commitment).await? {
            tracing::warn!("Note already claimed, skipping");
            return Ok(MintResult {
                signature: "already_claimed".to_string(),
                deposit_id,
                success: false,
            });
        }

        let discriminator = Self::get_instruction_discriminator("mint_simple");

        let mut data = Vec::new();
        data.extend_from_slice(&discriminator);
        data.extend_from_slice(&attestation.note_commitment);
        data.extend_from_slice(&attestation.amount.to_le_bytes());
        data.extend_from_slice(&attestation.block_height.to_le_bytes());

        let (bridge_config_pda, _) = self.derive_bridge_config_pda();
        let (deposit_intent_pda, _) = self.derive_deposit_intent_pda(user, deposit_id);
        let (claim_tracker_pda, _) = self.derive_claim_tracker_pda(&attestation.note_commitment);
        let (szec_mint_pda, _) = self.derive_szec_mint_pda();
        let (mint_authority_pda, _) = self.derive_mint_authority_pda();
        
        // Ensure user's ATA exists (create if needed)
        let user_token_account = self.ensure_ata_exists(user, &szec_mint_pda).await?;

        let accounts = vec![
            AccountMeta::new_readonly(self.payer.pubkey(), true),
            AccountMeta::new(self.payer.pubkey(), true),
            AccountMeta::new(bridge_config_pda, false),
            AccountMeta::new(deposit_intent_pda, false),
            AccountMeta::new(claim_tracker_pda, false),
            AccountMeta::new(szec_mint_pda, false),
            AccountMeta::new_readonly(mint_authority_pda, false),
            AccountMeta::new_readonly(*user, false),
            AccountMeta::new(user_token_account, false),
            AccountMeta::new_readonly(ata_program_id(), false),
            AccountMeta::new_readonly(token_program_id(), false),
            AccountMeta::new_readonly(system_program_id(), false),
        ];

        let instruction = Instruction {
            program_id: self.program_id,
            accounts,
            data,
        };

        let recent_blockhash = self.get_latest_blockhash().await?;
        let message = Message::new(&[instruction], Some(&self.payer.pubkey()));
        let mut transaction = Transaction::new_unsigned(message);
        transaction.sign(&[&*self.payer], recent_blockhash);

        match self.send_transaction(&transaction).await {
            Ok(signature) => {
                tracing::info!("Mint successful! TX: {}", signature);
                tracing::info!("   User: {}", user);
                tracing::info!("   Amount: {} zatoshi", attestation.amount);
                Ok(MintResult {
                    signature: signature.to_string(),
                    deposit_id,
                    success: true,
                })
            }
            Err(e) => {
                tracing::error!("Mint failed: {}", e);
                Err(e)
            }
        }
    }
}