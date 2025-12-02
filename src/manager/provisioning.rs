//! Enclave Provisioning Module
//! 
//! Handles:
//! - UFVK sealing (in-memory for now, TEE later)
//! - Enclave keypair generation (Ed25519)
//! - Provisioning status tracking
//! - Deposit attestation signing

use anyhow::Result;
use blake2::{Blake2b512, Digest};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Signature, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

// ============================================================================
// SERDE HELPERS FOR LARGE ARRAYS
// ============================================================================

mod serde_bytes_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            hex::encode(bytes).serialize(serializer)
        } else {
            bytes.as_slice().serialize(serializer)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            bytes.try_into().map_err(|_| serde::de::Error::custom("expected 64 bytes"))
        } else {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            bytes.try_into().map_err(|_| serde::de::Error::custom("expected 64 bytes"))
        }
    }
}

mod serde_bytes_32 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            hex::encode(bytes).serialize(serializer)
        } else {
            bytes.as_slice().serialize(serializer)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            bytes.try_into().map_err(|_| serde::de::Error::custom("expected 32 bytes"))
        } else {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            bytes.try_into().map_err(|_| serde::de::Error::custom("expected 32 bytes"))
        }
    }
}

// ============================================================================
// ATTESTATION TYPES
// ============================================================================

/// Deposit attestation - signed proof that enclave detected a Zcash deposit
/// 
/// This struct matches the `AttestationInput` in the Arcium encrypted instructions:
/// - note_commitment: [u8; 32]
/// - amount: u64
/// - recipient_solana: [u8; 32]
/// - block_height: u64
/// - enclave_signature: [u8; 64]
/// - enclave_pubkey: [u8; 32]
/// 
/// Total size: 32 + 8 + 32 + 8 + 64 + 32 = 176 bytes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositAttestation {
    #[serde(with = "serde_bytes_32")]
    pub note_commitment: [u8; 32],
    pub amount: u64,
    #[serde(with = "serde_bytes_32")]
    pub recipient_solana: [u8; 32],
    pub block_height: u64,
    #[serde(with = "serde_bytes_64")]
    pub enclave_signature: [u8; 64],
    #[serde(with = "serde_bytes_32")]
    pub enclave_pubkey: [u8; 32],
}

impl DepositAttestation {
    /// Serialize for Solana program consumption
    /// Order matches AttestationInput struct in encrypted-ixs
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(176);
        bytes.extend_from_slice(&self.note_commitment);       // 32 bytes
        bytes.extend_from_slice(&self.amount.to_le_bytes());  // 8 bytes
        bytes.extend_from_slice(&self.recipient_solana);      // 32 bytes
        bytes.extend_from_slice(&self.block_height.to_le_bytes()); // 8 bytes
        bytes.extend_from_slice(&self.enclave_signature);     // 64 bytes
        bytes.extend_from_slice(&self.enclave_pubkey);        // 32 bytes
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 176 {
            anyhow::bail!("Invalid attestation length: expected 176, got {}", bytes.len());
        }

        let mut note_commitment = [0u8; 32];
        note_commitment.copy_from_slice(&bytes[0..32]);

        let amount = u64::from_le_bytes(bytes[32..40].try_into().unwrap());

        let mut recipient_solana = [0u8; 32];
        recipient_solana.copy_from_slice(&bytes[40..72]);

        let block_height = u64::from_le_bytes(bytes[72..80].try_into().unwrap());

        let mut enclave_signature = [0u8; 64];
        enclave_signature.copy_from_slice(&bytes[80..144]);

        let mut enclave_pubkey = [0u8; 32];
        enclave_pubkey.copy_from_slice(&bytes[144..176]);

        Ok(Self {
            note_commitment,
            amount,
            recipient_solana,
            block_height,
            enclave_signature,
            enclave_pubkey,
        })
    }
}

// ============================================================================
// ENCLAVE PROVISIONER
// ============================================================================

/// Manages enclave provisioning and UFVK sealing
#[derive(Clone)]
pub struct EnclaveProvisioner {
    /// The sealed UFVK (once provisioned)
    /// In production: use SGX sealing or AWS Nitro attestation
    sealed_ufvk: Arc<Mutex<Option<String>>>,
    
    /// Enclave's Ed25519 keypair (for signing attestations)
    enclave_keypair: Arc<SigningKey>,
}

/// Request to provision the enclave with UFVK
#[derive(Debug, Clone, Deserialize)]
pub struct ProvisionRequest {
    pub ufvk: String,
    pub bridge_ua: String,
    pub admin_signature: String,
}

/// Response after successful provisioning
#[derive(Debug, Serialize)]
pub struct ProvisionResponse {
    pub enclave_pubkey: String, // Hex-encoded
    pub status: String,
}

impl EnclaveProvisioner {
    /// Create a new enclave provisioner
    /// Generates a new Ed25519 keypair for attestation signing
    pub fn new() -> Self {
        let mut csprng = OsRng;
        let keypair = SigningKey::generate(&mut csprng);
        
        tracing::info!("Generated enclave keypair");
        tracing::info!("   Pubkey: {}", hex::encode(keypair.verifying_key().to_bytes()));
        
        Self {
            sealed_ufvk: Arc::new(Mutex::new(None)),
            enclave_keypair: Arc::new(keypair),
        }
    }
    
    /// Get the enclave's public key (for verification)
    pub fn enclave_pubkey(&self) -> VerifyingKey {
        self.enclave_keypair.verifying_key()
    }
    
    /// Get the enclave's public key as bytes
    pub fn enclave_pubkey_bytes(&self) -> [u8; 32] {
        self.enclave_keypair.verifying_key().to_bytes()
    }
    
    /// Get the enclave's keypair (for signing)
    pub fn enclave_keypair(&self) -> Arc<SigningKey> {
        self.enclave_keypair.clone()
    }
    
    /// Provision the enclave with a UFVK
    pub fn provision(&self, req: ProvisionRequest) -> Result<ProvisionResponse> {
        // 1. Validate UFVK format
        if !req.ufvk.starts_with("uviewtest1") && !req.ufvk.starts_with("uview1") {
            anyhow::bail!("Invalid UFVK format: must start with 'uview' or 'uviewtest1'");
        }
        
        // 2. Check if already provisioned
        let mut sealed = self.sealed_ufvk.lock().unwrap();
        if sealed.is_some() {
            anyhow::bail!("UFVK already provisioned. Restart enclave to re-provision.");
        }
        
        // 3. TODO: Verify admin signature
        // In production: verify admin_signature over BLAKE2b(ufvk || bridge_ua)
        tracing::warn!("Admin signature verification not implemented (development mode)");
        
        // 4. Seal UFVK (in production: use SGX sealing)
        *sealed = Some(req.ufvk.clone());
        
        tracing::info!("Enclave provisioned with UFVK");
        tracing::info!("   UFVK: {}...", &req.ufvk[..30.min(req.ufvk.len())]);
        tracing::info!("   Bridge UA: {}", req.bridge_ua);
        
        Ok(ProvisionResponse {
            enclave_pubkey: hex::encode(self.enclave_keypair.verifying_key().to_bytes()),
            status: "provisioned".to_string(),
        })
    }
    
    /// Get the sealed UFVK (for internal use only)
    pub fn get_ufvk(&self) -> Result<String> {
        let sealed = self.sealed_ufvk.lock().unwrap();
        sealed.clone()
            .ok_or_else(|| anyhow::anyhow!("UFVK not provisioned. Call /provision first."))
    }
    
    /// Check if the enclave has been provisioned
    pub fn is_provisioned(&self) -> bool {
        self.sealed_ufvk.lock().unwrap().is_some()
    }

    // ========================================================================
    // ATTESTATION SIGNING
    // ========================================================================

    /// Sign a deposit attestation
    /// 
    /// This proves the enclave detected a valid Zcash deposit.
    /// The signature covers: BLAKE2b-512(note_commitment || amount || recipient || block_height)
    pub fn sign_attestation(
        &self,
        note_commitment: [u8; 32],
        amount: u64,
        recipient_solana: [u8; 32],
        block_height: u64,
    ) -> Result<DepositAttestation> {
        // Ensure we're provisioned
        if !self.is_provisioned() {
            anyhow::bail!("Cannot sign attestation: enclave not provisioned");
        }

        // Build message to sign: BLAKE2b-512(note_commitment || amount || recipient || block_height)
        let mut hasher = Blake2b512::new();
        hasher.update(&note_commitment);
        hasher.update(&amount.to_le_bytes());
        hasher.update(&recipient_solana);
        hasher.update(&block_height.to_le_bytes());
        let message_hash = hasher.finalize();

        // Sign with enclave keypair
        let signature: Signature = self.enclave_keypair.sign(&message_hash);

        tracing::info!(
            "Signed attestation: amount={} zatoshi, block={}, recipient={}...",
            amount,
            block_height,
            hex::encode(&recipient_solana[..8])
        );

        Ok(DepositAttestation {
            note_commitment,
            amount,
            recipient_solana,
            block_height,
            enclave_signature: signature.to_bytes(),
            enclave_pubkey: self.enclave_keypair.verifying_key().to_bytes(),
        })
    }

    /// Verify an attestation signature
    pub fn verify_attestation(attestation: &DepositAttestation) -> Result<bool> {
        // Rebuild message hash
        let mut hasher = Blake2b512::new();
        hasher.update(&attestation.note_commitment);
        hasher.update(&attestation.amount.to_le_bytes());
        hasher.update(&attestation.recipient_solana);
        hasher.update(&attestation.block_height.to_le_bytes());
        let message_hash = hasher.finalize();

        // Verify signature
        let pubkey = VerifyingKey::from_bytes(&attestation.enclave_pubkey)
            .map_err(|e| anyhow::anyhow!("Invalid pubkey: {}", e))?;
        let signature = Signature::from_bytes(&attestation.enclave_signature);

        Ok(pubkey.verify(&message_hash, &signature).is_ok())
    }
}

impl Default for EnclaveProvisioner {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_provisioner_creation() {
        let provisioner = EnclaveProvisioner::new();
        assert!(!provisioner.is_provisioned());
        
        let pubkey = provisioner.enclave_pubkey();
        assert_eq!(pubkey.to_bytes().len(), 32);
    }
    
    #[test]
    fn test_provisioning() {
        let provisioner = EnclaveProvisioner::new();
        
        let req = ProvisionRequest {
            ufvk: "uviewtest1test".to_string(),
            bridge_ua: "utest1test".to_string(),
            admin_signature: "test_sig".to_string(),
        };
        
        let response = provisioner.provision(req).unwrap();
        assert_eq!(response.status, "provisioned");
        assert!(provisioner.is_provisioned());
        
        let ufvk = provisioner.get_ufvk().unwrap();
        assert_eq!(ufvk, "uviewtest1test");
    }
    
    #[test]
    fn test_double_provision_fails() {
        let provisioner = EnclaveProvisioner::new();
        
        let req = ProvisionRequest {
            ufvk: "uviewtest1test".to_string(),
            bridge_ua: "utest1test".to_string(),
            admin_signature: "test_sig".to_string(),
        };
        
        provisioner.provision(req.clone()).unwrap();
        let result = provisioner.provision(req);
        assert!(result.is_err());
    }

    #[test]
    fn test_attestation_signing() {
        let provisioner = EnclaveProvisioner::new();
        
        let req = ProvisionRequest {
            ufvk: "uviewtest1test".to_string(),
            bridge_ua: "utest1test".to_string(),
            admin_signature: "test_sig".to_string(),
        };
        provisioner.provision(req).unwrap();
        
        let note_commitment = [1u8; 32];
        let amount = 1_000_000u64;
        let recipient_solana = [2u8; 32];
        let block_height = 12345u64;
        
        let attestation = provisioner
            .sign_attestation(note_commitment, amount, recipient_solana, block_height)
            .unwrap();
        
        assert!(EnclaveProvisioner::verify_attestation(&attestation).unwrap());
        assert_eq!(attestation.amount, amount);
        assert_eq!(attestation.to_bytes().len(), 176);
    }

    #[test]
    fn test_attestation_serialization_roundtrip() {
        let provisioner = EnclaveProvisioner::new();
        
        let req = ProvisionRequest {
            ufvk: "uviewtest1test".to_string(),
            bridge_ua: "utest1test".to_string(),
            admin_signature: "test_sig".to_string(),
        };
        provisioner.provision(req).unwrap();
        
        let original = provisioner
            .sign_attestation([3u8; 32], 5_000_000, [4u8; 32], 99999)
            .unwrap();
        
        let bytes = original.to_bytes();
        let recovered = DepositAttestation::from_bytes(&bytes).unwrap();
        
        assert_eq!(original.note_commitment, recovered.note_commitment);
        assert_eq!(original.amount, recovered.amount);
        assert_eq!(original.enclave_signature, recovered.enclave_signature);
    }

    #[test]
    fn test_attestation_fails_without_provision() {
        let provisioner = EnclaveProvisioner::new();
        let result = provisioner.sign_attestation([0u8; 32], 100, [0u8; 32], 1);
        assert!(result.is_err());
    }
}