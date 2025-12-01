//! Complete Orchard scanner with real trial decryption

use anyhow::Result;
use orchard::keys::{FullViewingKey, IncomingViewingKey, Scope, PreparedIncomingViewingKey};
use orchard::note_encryption::{CompactAction, OrchardDomain};
use zcash_note_encryption::{try_compact_note_decryption, EphemeralKeyBytes};
use std::collections::HashSet;

// Macro for safe array slicing
macro_rules! array_ref {
    ($arr:expr, $offset:expr, $len:expr) => {{
        {
            #[inline]
            fn as_array<T>(slice: &[T]) -> &[T; $len] {
                unsafe { &*(slice.as_ptr() as *const [T; $len]) }
            }
            as_array(&$arr[$offset..$offset + $len])
        }
    }};
}

pub struct OrchardScanner {
    _fvk: FullViewingKey,
    _ivk: IncomingViewingKey,
    prepared_ivk: PreparedIncomingViewingKey,
    seen_nullifiers: HashSet<Vec<u8>>,
}

impl OrchardScanner {
    pub fn new(fvk_bytes: &[u8; 96]) -> Result<Self> {
        let fvk = FullViewingKey::from_bytes(fvk_bytes)
            .ok_or_else(|| anyhow::anyhow!("Invalid FVK bytes"))?;
        
        let ivk = fvk.to_ivk(Scope::External);
        let prepared_ivk = PreparedIncomingViewingKey::new(&ivk);
        
        Ok(Self {
            _fvk: fvk,
            _ivk: ivk,
            prepared_ivk,
            seen_nullifiers: HashSet::new(),
        })
    }

    /// Try to decrypt a compact Orchard action
    pub fn try_decrypt_action(
        &mut self,
        nullifier: &[u8],
        cmx: &[u8],
        ephemeral_key: &[u8],
        ciphertext: &[u8],
    ) -> Option<u64> {
        // Track nullifier
        self.seen_nullifiers.insert(nullifier.to_vec());
        
        // Validate sizes
        if ephemeral_key.len() != 32 || cmx.len() != 32 || ciphertext.len() != 52 {
            return None;
        }

        // Convert to fixed-size arrays
        let mut nf_bytes = [0u8; 32];
        nf_bytes.copy_from_slice(nullifier);
        
        let mut cmx_bytes = [0u8; 32];
        cmx_bytes.copy_from_slice(cmx);
        
        let mut epk_bytes = [0u8; 32];
        epk_bytes.copy_from_slice(ephemeral_key);

        // Create compact action - use EphemeralKeyBytes from zcash_note_encryption
        let compact_action = CompactAction::from_parts(
            orchard::note::Nullifier::from_bytes(&nf_bytes).unwrap(),
            orchard::note::ExtractedNoteCommitment::from_bytes(&cmx_bytes).unwrap(),
            EphemeralKeyBytes(epk_bytes),
            *array_ref![ciphertext, 0, 52],
        );

        // Create domain
        let domain = OrchardDomain::for_compact_action(&compact_action);

        // Try to decrypt
        match try_compact_note_decryption(&domain, &self.prepared_ivk, &compact_action) {
            Some((note, _recipient)) => {
                Some(note.value().inner())
            }
            None => None,
        }
    }

    pub fn nullifier_count(&self) -> usize {
        self.seen_nullifiers.len()
    }
}

#[derive(Default, Debug)]
pub struct BalanceResult {
    pub received_value: u64,
    pub received_count: usize,
    pub blocks_scanned: u64,
    pub actions_scanned: u64,
    pub decryption_attempts: u64,
}

