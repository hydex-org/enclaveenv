/// Address Manager - Native Orchard Diversification
///
/// This module implements the CORRECT Zcash address derivation model:
/// - One FVK → Many diversified addresses (using diversifier index)
/// - No child key derivation
/// - No per-user keys
/// - Standard Zcash wallet behavior
use anyhow::Result;
use orchard::keys::{FullViewingKey, Scope};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::{env, fs};
use zcash_address::unified::{self, Address, Container, Encoding, Receiver};

use crate::client::S3Client;

/// Default path for persisted mappings
const MAPPINGS_FILE: &str = "data/address_mappings.json";

/// Serializable mapping entry
#[derive(Serialize, Deserialize, Clone)]
struct MappingEntry {
    solana_pubkey: String,
    diversifier_index: u32,
    zcash_address: String,
}

/// Manages deposit address generation using native Orchard diversification
pub struct AddressManager {
    /// The one FVK that views all addresses
    fvk: FullViewingKey,

    /// Network (for encoding)
    network: zcash_address::Network,

    /// Next diversifier index to use
    next_index: Arc<Mutex<u32>>,

    /// Mapping: solana_pubkey → (diversifier_index, zcash_address)
    /// This allows us to track which user owns which deposit address
    user_mappings: Arc<Mutex<HashMap<String, (u32, String)>>>,

    s3_client: S3Client,
}

impl AddressManager {
    /// Create a new AddressManager from a UFVK string
    pub async fn from_ufvk(ufvk_str: &str) -> Result<Self> {
        let s3_client = S3Client::new("hydex-keypair-bucket", "address_mappings.json").await?;
        let msg = s3_client.check_mappings_file().await?;
        println!("{}", msg);
        // Decode UFVK
        let (network, ufvk) = unified::Ufvk::decode(ufvk_str)
            .map_err(|e| anyhow::anyhow!("Failed to decode UFVK: {:?}", e))?;

        // Extract Orchard FVK
        let mut fvk_bytes: Option<[u8; 96]> = None;
        for item in ufvk.items() {
            if let unified::Fvk::Orchard(bytes) = item {
                if bytes.len() == 96 {
                    let mut arr = [0u8; 96];
                    arr.copy_from_slice(&bytes);
                    fvk_bytes = Some(arr);
                    break;
                }
            }
        }

        let fvk_bytes = fvk_bytes.ok_or_else(|| anyhow::anyhow!("No Orchard FVK in UFVK"))?;

        // Parse FVK
        let fvk = FullViewingKey::from_bytes(&fvk_bytes)
            .ok_or_else(|| anyhow::anyhow!("Invalid FVK bytes"))?;

        
        Ok(Self {
            fvk,
            network,
            next_index: Arc::new(Mutex::new(0)),
            user_mappings: Arc::new(Mutex::new(HashMap::new())),
            s3_client,
        })
    }

    /// Generate a new deposit address for a Solana user
    ///
    /// This is the STANDARD Zcash diversification pattern:
    /// - Takes the next available diversifier index
    /// - Derives Orchard address: fvk.address_at(index, Scope::External)
    /// - Note: address_at handles invalid diversifiers internally
    /// - Wraps in a Unified Address
    /// - Stores mapping: solana_pubkey → (index, address)
    ///
    /// Returns: (unified_address, diversifier_index)
    pub async fn generate_deposit_address(&self, solana_pubkey: &str) -> Result<(String, u32)> {
        // Check if user already has an address
        {
            let mappings = self.user_mappings.lock().unwrap();
            if let Some((index, address)) = mappings.get(solana_pubkey) {
                return Ok((address.clone(), *index));
            }
        }

        // Get next diversifier index
        let div_index = {
            let mut next = self.next_index.lock().unwrap();
            let current = *next;
            *next += 1;
            current
        };

        // Derive Orchard address using NATIVE Zcash diversification
        // address_at returns Address directly - it handles invalid diversifiers internally
        let orchard_address = self.fvk.address_at(div_index, Scope::External);

        // Build Unified Address
        let ua = Address::try_from_items(vec![Receiver::Orchard(
            orchard_address.to_raw_address_bytes(),
        )])?;

        let ua_string = ua.encode(&self.network);

        // Store mapping
        {
            let mut mappings = self.user_mappings.lock().unwrap();
            mappings.insert(solana_pubkey.to_string(), (div_index, ua_string.clone()));
        }

        // Persist to disk
        if let Err(e) = self.save_mappings().await {
            tracing::warn!("Failed to persist mappings: {}", e);
        }

        Ok((ua_string, div_index))
    }

    /// Lookup existing address for a user
    /// Returns (address, diversifier_index)
    pub fn get_user_address(&self, solana_pubkey: &str) -> Option<(String, u32)> {
        let mappings = self.user_mappings.lock().unwrap();
        mappings
            .get(solana_pubkey)
            .map(|(idx, addr)| (addr.clone(), *idx))
    }

    /// Get all user mappings (for persistence/recovery)
    pub fn get_all_mappings(&self) -> HashMap<String, (u32, String)> {
        let mappings = self.user_mappings.lock().unwrap();
        mappings.clone()
    }

    /// Restore mappings (for persistence/recovery)
    pub fn restore_mappings(&self, mappings: HashMap<String, (u32, String)>) -> Result<()> {
        let mut user_mappings = self.user_mappings.lock().unwrap();
        *user_mappings = mappings.clone();

        // Update next_index to be max(existing indices) + 1
        if let Some(max_index) = mappings.values().map(|(idx, _)| *idx).max() {
            let mut next = self.next_index.lock().unwrap();
            *next = max_index + 1;
        }

        Ok(())
    }

    /// Save mappings to disk
    pub async fn save_mappings(&self) -> Result<()> {
        let mappings = self.user_mappings.lock().unwrap();

        let entries: Vec<MappingEntry> = mappings
            .iter()
            .map(|(solana_pk, (idx, addr))| MappingEntry {
                solana_pubkey: solana_pk.clone(),
                diversifier_index: *idx,
                zcash_address: addr.clone(),
            })
            .collect();

        // Ensure data directory exists
        if let Some(parent) = Path::new(MAPPINGS_FILE).parent() {
            fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(&entries)?;
        fs::write(MAPPINGS_FILE, json)?;

        tracing::info!(
            "Saved {} address mappings to {}",
            entries.len(),
            MAPPINGS_FILE
        );

        self.s3_client.replace_and_upload();
        Ok(())
    }

    /// Load mappings from disk
    pub fn load_mappings(&self) -> Result<usize> {
        if !Path::new(MAPPINGS_FILE).exists() {
            tracing::info!("No existing mappings file found at {}", MAPPINGS_FILE);
            return Ok(0);
        }

        let json = fs::read_to_string(MAPPINGS_FILE)?;
        let entries: Vec<MappingEntry> = serde_json::from_str(&json)?;

        let mut mappings = HashMap::new();
        let mut max_index = 0u32;

        for entry in &entries {
            mappings.insert(
                entry.solana_pubkey.clone(),
                (entry.diversifier_index, entry.zcash_address.clone()),
            );
            if entry.diversifier_index > max_index {
                max_index = entry.diversifier_index;
            }
        }

        // Restore to memory
        {
            let mut user_mappings = self.user_mappings.lock().unwrap();
            *user_mappings = mappings;
        }

        // Update next_index
        {
            let mut next = self.next_index.lock().unwrap();
            *next = max_index + 1;
        }

        let count = entries.len();
        tracing::info!("Loaded {} address mappings from {}", count, MAPPINGS_FILE);
        Ok(count)
    }

    pub fn ensure_address_mappings_exists() -> bool {
        let path = Path::new("../../data/address_mappings.json");

        if path.exists() && path.is_file() {
            return true;
        } else {
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_generation() {
        // This will fail without a valid UFVK, but demonstrates the API
        // In real tests, you'd use a UFVK from DKG

        // Mock test - just validate that indices increment
        let solana_pk1 = "user1_solana_pubkey";
        let solana_pk2 = "user2_solana_pubkey";

        // Would call: manager.generate_deposit_address(solana_pk1)
        // Expect: (address1, 0)

        // Would call: manager.generate_deposit_address(solana_pk2)
        // Expect: (address2, 1)

        // Calling again with solana_pk1 returns same address
    }
}
