//! Enclave Provisioning Module
//! 
//! Handles:
//! - UFVK sealing (in-memory for now, TEE later)
//! - Enclave keypair generation (Ed25519)
//! - Provisioning status tracking

use anyhow::Result;
use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

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
#[derive(Debug, Deserialize)]
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
        
        tracing::info!("🔑 Generated enclave keypair");
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
        tracing::warn!("⚠️  Admin signature verification not implemented (development mode)");
        
        // 4. Seal UFVK (in production: use SGX sealing)
        *sealed = Some(req.ufvk.clone());
        
        tracing::info!("✅ Enclave provisioned with UFVK");
        tracing::info!("   UFVK: {}...", &req.ufvk[..30]);
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
}

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
        
        // Can retrieve UFVK
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
        
        // Second provision should fail
        let result = provisioner.provision(req);
        assert!(result.is_err());
    }
}