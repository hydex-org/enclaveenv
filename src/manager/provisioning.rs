//! Enclave Provisioning Module
//!
//! Handles UFVK sealing and Ed25519 keypair persistence.
//! Uses file-based storage for development, AWS Secrets Manager for production.

use anyhow::Result;
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Signature, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
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
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(176);
        bytes.extend_from_slice(&self.note_commitment);
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        bytes.extend_from_slice(&self.recipient_solana);
        bytes.extend_from_slice(&self.block_height.to_le_bytes());
        bytes.extend_from_slice(&self.enclave_signature);
        bytes.extend_from_slice(&self.enclave_pubkey);
        bytes
    }

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

const DATA_DIR: &str = "data/enclave";
const KEYPAIR_FILE: &str = "ed25519-keypair.json";
const UFVK_FILE: &str = "ufvk.txt";

#[derive(Clone)]
pub struct EnclaveProvisioner {
    sealed_ufvk: Arc<Mutex<Option<String>>>,
    enclave_keypair: Arc<SigningKey>,
    data_dir: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProvisionRequest {
    pub ufvk: String,
    pub bridge_ua: String,
    pub admin_signature: String,
}

#[derive(Debug, Serialize)]
pub struct ProvisionResponse {
    pub enclave_pubkey: String,
    pub status: String,
}

impl EnclaveProvisioner {
    /// Create a new enclave provisioner with file-based persistence
    pub async fn new() -> Result<Self> {
        let data_dir = PathBuf::from(DATA_DIR);
        std::fs::create_dir_all(&data_dir)?;
        
        tracing::info!("Enclave data directory: {}", data_dir.display());

        // Load or generate keypair
        let keypair = Self::load_or_generate_keypair(&data_dir)?;
        tracing::info!("Enclave keypair ready");
        tracing::info!("   Pubkey: {}", hex::encode(keypair.verifying_key().to_bytes()));

        // Load existing UFVK if available
        let sealed_ufvk = Self::load_ufvk(&data_dir);
        if sealed_ufvk.is_some() {
            tracing::info!("Loaded existing UFVK from file");
        } else {
            tracing::info!("No UFVK found - waiting for provisioning");
        }

        Ok(Self {
            sealed_ufvk: Arc::new(Mutex::new(sealed_ufvk)),
            enclave_keypair: Arc::new(keypair),
            data_dir,
        })
    }

    fn load_or_generate_keypair(data_dir: &PathBuf) -> Result<SigningKey> {
        let keypair_path = data_dir.join(KEYPAIR_FILE);
        
        // Try to load existing
        if keypair_path.exists() {
            let contents = std::fs::read_to_string(&keypair_path)?;
            let bytes: Vec<u8> = serde_json::from_str(&contents)?;
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                tracing::info!("Loaded existing enclave keypair from file");
                return Ok(SigningKey::from_bytes(&arr));
            }
        }

        // Generate new
        let mut csprng = OsRng;
        let keypair = SigningKey::generate(&mut csprng);

        // Save
        let bytes_json = serde_json::to_string(&keypair.to_bytes().to_vec())?;
        std::fs::write(&keypair_path, bytes_json)?;
        tracing::info!("Generated and saved new enclave keypair");

        Ok(keypair)
    }

    fn load_ufvk(data_dir: &PathBuf) -> Option<String> {
        let ufvk_path = data_dir.join(UFVK_FILE);
        std::fs::read_to_string(&ufvk_path).ok()
    }

    fn persist_ufvk(&self, ufvk: &str) -> Result<()> {
        let ufvk_path = self.data_dir.join(UFVK_FILE);
        std::fs::write(&ufvk_path, ufvk)?;
        tracing::info!("UFVK persisted to file");
        Ok(())
    }

    pub fn enclave_pubkey(&self) -> VerifyingKey {
        self.enclave_keypair.verifying_key()
    }

    pub fn enclave_pubkey_bytes(&self) -> [u8; 32] {
        self.enclave_keypair.verifying_key().to_bytes()
    }

    pub fn enclave_keypair(&self) -> Arc<SigningKey> {
        self.enclave_keypair.clone()
    }

    pub async fn provision(&self, req: ProvisionRequest) -> Result<ProvisionResponse> {
        if !req.ufvk.starts_with("uviewtest1") && !req.ufvk.starts_with("uview1") {
            anyhow::bail!("Invalid UFVK format");
        }

        {
            let sealed = self.sealed_ufvk.lock().unwrap();
            if sealed.is_some() {
                anyhow::bail!("UFVK already provisioned");
            }
        }

        tracing::warn!("Admin signature verification not implemented");

        self.persist_ufvk(&req.ufvk)?;

        {
            let mut sealed = self.sealed_ufvk.lock().unwrap();
            *sealed = Some(req.ufvk.clone());
        }

        tracing::info!("Enclave provisioned with UFVK");

        Ok(ProvisionResponse {
            enclave_pubkey: hex::encode(self.enclave_keypair.verifying_key().to_bytes()),
            status: "provisioned".to_string(),
        })
    }

    pub fn get_ufvk(&self) -> Result<String> {
        let sealed = self.sealed_ufvk.lock().unwrap();
        sealed.clone().ok_or_else(|| anyhow::anyhow!("UFVK not provisioned"))
    }

    pub fn is_provisioned(&self) -> bool {
        self.sealed_ufvk.lock().unwrap().is_some()
    }

    pub fn sign_attestation(
        &self,
        note_commitment: [u8; 32],
        amount: u64,
        recipient_solana: [u8; 32],
        block_height: u64,
    ) -> Result<DepositAttestation> {
        if !self.is_provisioned() {
            anyhow::bail!("Cannot sign attestation: enclave not provisioned");
        }

        let mut message = Vec::with_capacity(80);
        message.extend_from_slice(&note_commitment);
        message.extend_from_slice(&amount.to_le_bytes());
        message.extend_from_slice(&recipient_solana);
        message.extend_from_slice(&block_height.to_le_bytes());

        let signature: Signature = self.enclave_keypair.sign(&message);

        Ok(DepositAttestation {
            note_commitment,
            amount,
            recipient_solana,
            block_height,
            enclave_signature: signature.to_bytes(),
            enclave_pubkey: self.enclave_keypair.verifying_key().to_bytes(),
        })
    }

    pub fn verify_attestation(attestation: &DepositAttestation) -> Result<bool> {
        let mut message = Vec::with_capacity(80);
        message.extend_from_slice(&attestation.note_commitment);
        message.extend_from_slice(&attestation.amount.to_le_bytes());
        message.extend_from_slice(&attestation.recipient_solana);
        message.extend_from_slice(&attestation.block_height.to_le_bytes());

        let pubkey = VerifyingKey::from_bytes(&attestation.enclave_pubkey)
            .map_err(|e| anyhow::anyhow!("Invalid pubkey: {}", e))?;
        let signature = Signature::from_bytes(&attestation.enclave_signature);

        Ok(pubkey.verify(&message, &signature).is_ok())
    }
}