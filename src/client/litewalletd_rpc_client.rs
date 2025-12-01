//! Real gRPC client for lightwalletd

use anyhow::Result;
use orchard::note_encryption::CompactAction;
use tokio_stream::StreamExt;
use tonic::{IntoRequest, Response, transport::Channel};

// Include generated protobuf code
pub mod wallet {
    tonic::include_proto!("cash.z.wallet.sdk.rpc");
}

use wallet::{
    BlockId, BlockRange, ChainSpec, CompactBlock,
    compact_tx_streamer_client::CompactTxStreamerClient,
};
use zcash_primitives::transaction::TxId;

use crate::client::wallet::CompactTx;

pub struct LightwalletdClient {
    client: CompactTxStreamerClient<Channel>,
    seen_nullifiers: Vec<u8>
}

impl LightwalletdClient {
    pub async fn connect(endpoint: String) -> Result<Self> {
        let client = CompactTxStreamerClient::connect(endpoint).await?;
        let seen_nullifiers = Vec::new();
        Ok(Self { seen_nullifiers, client })
    }

    pub async fn get_latest_block(&mut self) -> Result<u64> {
        let response = self.client.get_latest_block(ChainSpec {}).await?;

        Ok(response.into_inner().height)
    }

    pub async fn get_block_range(&mut self, start: u64, end: u64) -> Result<Vec<CompactBlock>> {
        let request = BlockRange {
            start: Some(BlockId {
                height: start,
                hash: vec![],
            }),
            end: Some(BlockId {
                height: end,
                hash: vec![],
            }),
        };

        let mut stream = self.client.get_block_range(request).await?.into_inner();

        let mut blocks = Vec::new();
        while let Some(block) = stream.next().await {
            blocks.push(block?);
        }

        Ok(blocks)
    }

    pub async fn get_block(
        &mut self,
        request: BlockId,
    ) -> Result<Response<CompactBlock>, tonic::Status> {
        let block = CompactTxStreamerClient::get_block(&mut self.client, request).await?;
        Ok(block)
    }

// pub async fn get_transaction(
//     &mut self,
//     request: TxId,
// ) -> Result<Response<CompactTx>, tonic::Status> {
//     let tx = self.client.get_transaction(request).await?;
    
//     Ok(tx)
// }
  // Try to decrypt a compact Orchard action
    // pub fn try_decrypt_action(
    //     &mut self,
    //     nullifier: &[u8],
    //     cmx: &[u8],
    //     ephemeral_key: &[u8],
    //     ciphertext: &[u8],
    // ) -> Option<u64> {
    //     // Track nullifier
    //     //let nullifier_vec = nullifier.to_vec();
    //     self.seen_nullifiers.insert(nullifier_vec.len(), &nullifier_vec);
        
    //     // Validate sizes
    //     if ephemeral_key.len() != 32 || cmx.len() != 32 || ciphertext.len() != 52 {
    //         return None;
    //     }

    //     // Convert to fixed-size arrays
    //     let mut nf_bytes = [0u8; 32];
    //     nf_bytes.copy_from_slice(nullifier);
        
    //     let mut cmx_bytes = [0u8; 32];
    //     cmx_bytes.copy_from_slice(cmx);
        
    //     let mut epk_bytes = [0u8; 32];
    //     epk_bytes.copy_from_slice(ephemeral_key);
    //     return Ok(0.)
    // }

}
