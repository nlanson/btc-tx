/*
    API module to make http requests to the Bitcoin JSON RPC

    Main net transactions to source data from local Bitcoin Core (Umbrel)
    Test net transaction to source data from https://testnet.bitcoinexplorer.org/ 
*/
use serde::Deserialize;
use crate::{
    util:: Network
};


#[derive(Debug, Deserialize)]
pub struct TxData {
    txid: String,
    hash: String,
    version: u32,
    size: u32,
    vsize: u32,
    weight: u32,
    locktime: u32,
    vin: Vec<InputData>,
    vout: Vec<OutputData>,
    hex: String,
    blockhash: String,
    confirmations: u32,
    time: u64, 
    blocktime: u64
}

#[derive(Debug, Deserialize)]
pub struct InputData {
    txid: String,
    vout: u32,
    scriptSig: ScriptSigData,
    txinwitness: Option<Vec<String>>,
    sequence: u32
}
#[derive(Debug, Deserialize)]
pub struct ScriptSigData {
    asm: String,
    hex: String
}

#[derive(Debug, Deserialize)]
pub struct OutputData {
    value: f64,
    n: u32,
    scriptPubKey: ScriptPubKeyData
}

#[derive(Debug, Deserialize)]
pub struct ScriptPubKeyData {
    asm: String,
    hex: String,
    address: String,
    r#type: String
}

pub enum APIErr {
    FailedToGet(),
    CannotDeserialize(),
    MissingVout(),
}

pub struct JsonRPC {
    network: Network,
    url: String
}

impl JsonRPC {
    pub fn new(network: &Network) -> Self {
        let (network, url) = match network {
            Network::Main => (Network::Main, String::from("https://bitcoinexplorer.org/api")),
            Network::Test => (Network::Test, String::from("https://testnet.bitcoinexplorer.org/api"))
        };
        
        Self {
            network,
            url
        }
    }
    
    #[tokio::main]
    pub async fn get_tx(&self, txid: &str) -> Result<TxData, APIErr> {
        let url = format!("{}/tx/{}", self.url, txid);
        let txd = match reqwest::get(url).await {
            Ok(x) => match x.json::<TxData>().await {
                Ok(x) => x,
                Err(_) => return Err(APIErr::CannotDeserialize())
            },
            Err(_) => return Err(APIErr::FailedToGet())
        };

        Ok(txd)
    }

    pub fn get_input_script_pub_key_hex(&self, txid: &str, vout: u32) -> Result<String, APIErr>  {
        let txd = Self::get_tx(self, txid)?;
    
        if vout as usize > txd.vout.len() {
            return Err(APIErr::MissingVout())
        }
    
        Ok(txd.vout[vout as usize].scriptPubKey.hex.clone())
    
    }
}