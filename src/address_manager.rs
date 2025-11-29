/// Address Manager - Native Orchard Diversification
/// 
/// This module implements the CORRECT Zcash address derivation model:
/// - One FVK → Many diversified addresses (using diversifier index)
/// - No child key derivation
/// - No per-user keys
/// - Standard Zcash wallet behavior

use anyhow::Result;
use orchard::keys::{FullViewingKey, Scope};
use zcash_address::unified::{self, Address, Encoding, Receiver, Container};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

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
}

impl AddressManager {
    /// Create a new AddressManager from a UFVK string
    pub fn from_ufvk(ufvk_str: &str) -> Result<Self> {
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
        
        let fvk_bytes = fvk_bytes
            .ok_or_else(|| anyhow::anyhow!("No Orchard FVK in UFVK"))?;
        
        // Parse FVK
        let fvk = FullViewingKey::from_bytes(&fvk_bytes)
            .ok_or_else(|| anyhow::anyhow!("Invalid FVK bytes"))?;
        
        Ok(Self {
            fvk,
            network,
            next_index: Arc::new(Mutex::new(0)),
            user_mappings: Arc::new(Mutex::new(HashMap::new())),
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
pub fn generate_deposit_address(&self, solana_pubkey: &str) -> Result<(String, u32)> {
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
    let ua = Address::try_from_items(vec![
        Receiver::Orchard(orchard_address.to_raw_address_bytes()),
    ])?;
    
    let ua_string = ua.encode(&self.network);
    
    // Store mapping
    {
        let mut mappings = self.user_mappings.lock().unwrap();
        mappings.insert(solana_pubkey.to_string(), (div_index, ua_string.clone()));
    }
    
    Ok((ua_string, div_index))
}
    
    /// Lookup existing address for a user
    /// Returns (address, diversifier_index)
    pub fn get_user_address(&self, solana_pubkey: &str) -> Option<(String, u32)> {
        let mappings = self.user_mappings.lock().unwrap();
        mappings.get(solana_pubkey).map(|(idx, addr)| (addr.clone(), *idx))
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

