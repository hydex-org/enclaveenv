// call rpc client getwallet

// make new account
// associate account with business functions
//

//enclave_state_client()

// let provisioner = Arc::new(EnclaveProvisioner::new());
// let manager = Arc::new(tokio::sync::Mutex::new(Some(self.address_manager.clone())));
// let enclave_state = EnclaveState {
//     provisioner,
//     address_manager: manager,
// };
// let provision_request = ProvisionRequest {
//     ufvk: deposit_address,
//     bridge_ua: "uviewtest1ggujlrd7jzmevn6vwyxxvm94pupz3z3cze4mgqsn2t8vanuecd5pw6vtqz8n8jmzs9p0ktgp5dxk7nl85w7lt8f4qxmua4t58tc0c2tn6yrzrchmd5zxse48esk7djvrh40txll0wmwrz3h3ysx5xlkjjuq4n8txlftpffz60t5p70lrjk300xe0rr52eq8ej2yrrlgzec66m3jwe3nscu0a8qe2f7066qlh9g439t5x99s0jete4m6r82h06xpksfgynvpzxuhes6pr24w0wzl5te9kel3rc5wk3yajw6y4gnjdl8yjwfgzc2ksnhhlapq3pceaqvkennyw4ynh4xws6qpjdl5yqytqk2a6jwr7d3rfhpw5qnm4ucstx5ltdl8pmhgq3ll2e5fnrndspkqrnnyt8kx4vkufhhmx9fu53uwrpwf445s48y3plhv3dj7zf5xwsyfzv97zn3cty5yqwr9ghecv23k8unn0ttf4fcv6j55wq77w"
//         .to_string(),
//     admin_signature: wallet,
// };
// let provision_response = provision_ufvk(
//     State(enclave_state),
//     Json(provision_request))
//     .await;

use actix_web::cookie::time::format_description::modifier::UnixTimestamp;
use actix_web::http::header::{HeaderMap, HeaderValue};
use actix_web::web::Payload;
// use crate::client::{
//     ZcashRpcClient, wallet::{BlockId, CompactBlock, CompactTx}, zcash_rpc_client::BlockchainInfo
// };
use actix_web::{web, App, HttpServer};
use anyhow::{bail, Context, Result};
use axum::extract::State;
use axum::Json;
//use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};

use std::io::Error;
use std::sync::Arc;
//use zcash_primitives::consensus::Network;
use crate::client::EnclaveState;
use crate::client::{self, EnclaveStateClient};
use clap::Parser;
//use client::zcash_rpc_client::ZcashRpcClient;
//use crate::client::ZcashRpcClient;
use crate::client::enclave_state_client;
use crate::client::provision_ufvk;
use crate::client::wallet::BlockId;
use crate::client::wallet::CompactBlock;
use crate::client::LightwalletdClient;
use crate::manager::AddressManager;
use crate::manager::EnclaveProvisioner;
use crate::manager::ProvisionRequest;
use crate::scanner::OrchardScanner;
use std::env;
use zcash_address::unified::Container;
use zcash_address::unified::Encoding;
use zcash_address::{unified, Network};
pub struct ZCashRpcClientService {
    //pub broadcast_rpc_client: ZcashRpcClient,
    pub read_only_rpc_client: LightwalletdClient,
    pub orchard_scanner: OrchardScanner,
    pub address_manager: AddressManager,
    pub enclave_state_client: EnclaveStateClient,
    pub enclave_provisioner: EnclaveProvisioner,
}

pub struct AuthChallengeResponse {
    pub challenge: String,
    pub nonce: String, // see note below
    pub expires_at: UnixTimestamp,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DepositAddressResponse {
    deposit_address: String,
    diversifier_index: u32,
    solana_pubkey: String,
    network: String,
    ufvk: String,
    note: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResponse{
    challenge: String,
    nonce: String,
    expires_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct DepositAddressRequest {
    solana_pubkey: String,
}
#[derive(Parser)]
#[command(name = "ufvk-scanner")]
#[command(about = "Scan Zcash blockchain for UFVK balance with REAL data", long_about = None)]
struct Cli {
    /// Unified Full Viewing Key
    #[arg(
        short,
        long,
        default_value = ""
    )]
    ufvk: String,

    /// Lightwalletd server URL
    #[arg(short, long, default_value = "https://testnet.zec.rocks:443")]
    server: String,

    /// Network (testnet or mainnet)
    #[arg(short, long, default_value = "testnet")]
    network: String,

    /// Number of blocks to scan (default: 1000)
    #[arg(short, long, default_value = "10000")]
    blocks: u64,

    /// Bridge address for context
    #[arg(short, long)]
    address: Option<String>,
}
// test comment
impl ZCashRpcClientService {
    pub async fn new() -> Result<Self> {
        let cli = Cli::parse();

        println!("\n=========================================");
        println!("   Hydex UFVK Real Balance Scanner");
        println!("=========================================\n");

        // Parse network
        let network = Network::Test;

        println!("Network:     {:?}", network);
        println!("Server:      {}", cli.server);
        println!("Scan depth:  {} blocks\n", cli.blocks);

        // Decode UFVK
        println!("=== Step 1: Decoding UFVK ===");

        let read_only_rpc_client = match LightwalletdClient::connect(cli.server.clone()).await {
            Ok(c) => {
                println!("✓");
                c
            }
            Err(e) => {
                println!("✗");
                println!("\n❌ Failed to connect: {}\n", e);
                println!("💡 Common issues:");
                println!("   • Server might be down");
                println!("   • Try a different server:");
                println!("     --server https://lightwalletd.testnet.electriccoin.co:9067");
                println!("   • Check your internet connection");
                return Err(e);
            }
        };

        // Decode UFVK
        println!("=== Step 1: Decoding UFVK ===");
        let decoded = match unified::Ufvk::decode(&cli.ufvk) {
            Ok((parsed_net, ufvk)) => {
                if parsed_net != network {
                    bail!("Network mismatch");
                }
                println!("✓ UFVK valid for {:?}", parsed_net);
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
                    println!("✓ Orchard FVK extracted (96 bytes)");
                    break;
                }
            }
        }

        let fvk_bytes =
            orchard_fvk_bytes.ok_or_else(|| anyhow::anyhow!("No Orchard FVK in UFVK"))?;

        // Create scanner
        //let mut scanner = OrchardScanner::new(&fvk_bytes)?;
        println!("✓ Scanner initialized\n");
        let mut orchard_scanner = OrchardScanner::new(&fvk_bytes)?;

        let mut address_manager = AddressManager::from_ufvk(&cli.ufvk)?;

        let mut enclave_state_client = EnclaveStateClient::new().await?;

        let mut enclave_provisioner = EnclaveProvisioner::new();
        // 🚀 RETURN THE SERVICE INSTANCE
        Ok(Self {
            //broadcast_rpc_client: broadcast_rpc_client,
            read_only_rpc_client: read_only_rpc_client,
            orchard_scanner: orchard_scanner,
            address_manager: address_manager,
            enclave_state_client: enclave_state_client,
            enclave_provisioner: enclave_provisioner,
        })
    }

    pub async fn emit_orchard(&mut self, data: Vec<u8>, height: u64) -> Result<CompactBlock> {
        let req = BlockId {
            height,
            hash: vec![], // optional
        };

        let block = &mut self.read_only_rpc_client.get_block(req).await?.into_inner();

        for tx in &block.vtx {
            // Scan each Orchard action
            for action in &tx.actions {
                //result.actions_scanned += 1;
                //result.decryption_attempts += 1;

                // Try to decrypt
                if let Some(value) = self.orchard_scanner.try_decrypt_action(
                    &action.nullifier,
                    &action.cmx,
                    &action.ephemeral_key,
                    &action.ciphertext,
                    Network::Test,
                ) {
                    //result.received_value += value;
                    //result.received_count += 1;
                    println!("  ✓ Found note: {:?}", value);
                } else {
                    println!("Failed to load Decrpted zatoshis")
                }
            }
        }
        Ok(block.clone())
    }

    pub async fn connect_wallet(&mut self, wallet: String) -> Result<DepositAddressResponse> {
        let url = "https://localhost:3000/api/deposit-address";

        let mut headers = HeaderMap::new();
        //const CONTENT_TYPE: _ = $0;

        let client = reqwest::Client::new();

        let req = DepositAddressRequest {
            solana_pubkey: wallet.into(),
        };
        let json = serde_json::to_string(&req)?;
        let resp = client
            .post("http://localhost:3001/api/deposit-address")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(json)
            .send()
            .await?;
        println!("Response: {:?}", resp);
        let parsed: DepositAddressResponse = resp.json().await?;
        Ok(parsed)
    }

    // module-scope type definition ✅


    pub async fn auth_challenge(
        &mut self,
        wallet: String,
        deposit_address: String,
    ) -> Result<DepositAddressResponse> {
        let url = "https://localhost:3000/api/deposit-address";

        let mut headers = HeaderMap::new();
        //const CONTENT_TYPE: _ = $0;

        let client = reqwest::Client::new();

        let req = DepositAddressRequest {
            solana_pubkey: wallet.into(),
        };
        let json = serde_json::to_string(&req)?;
        let resp = client
            .get("http://localhost:8080/bridge-address")
            .json(&req)
            .send()
            .await?;

        let parsed: DepositAddressResponse = resp.json().await?;
        Ok(parsed)
    }
}
// impl zcash_rpc_client_service{

// }

// impl zcash_rpc_client_service {

//     pub fn new(){}
// }

// pub async fn ping() -> String {
//     "Ping".to_string()
// }

//     pub async fn emit_orchard(
//     block_hash: &str,
// ) -> String{
//     let block = rpc_client.getblock(block_hash).await;
//     "".to_string()
// }

// let mut nf_bytes = [0u8; 32];
//         nf_bytes.copy_from_slice(nullifier);

//         let mut cmx_bytes = [0u8; 32];
//         cmx_bytes.copy_from_slice(cmx);

//         let mut epk_bytes = [0u8; 32];
//         epk_bytes.copy_from_slice(ephemeral_key);
