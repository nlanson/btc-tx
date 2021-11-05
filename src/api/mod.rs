/*
    API module to make http requests to the ElectrumX Server.
    A custom server can be specified or a default one will be used. (blockstream)

    Public electrum servers sourced from https://1209k.com/bitcoin-eye/ele.php?chain=btc
*/

use bitcoin_hashes::hex::FromHex;
use crate::{
    Client, 
    ElectrumApi,
    util::bytes::decode_02x,
    util::Network
};

pub struct Electrum {
    client: Client
}

#[derive(Debug)]
pub enum ElectrumErr {
    FailedToConnect,
    UnknownGenesis(String),
    FailedToGet(),
    MissingVout(),
}

/**
    Electrum client notes:
        - Need to check if the client returned is for testnet or mainnet. 
          Hopefully this can be done through a call...
*/
impl Electrum {
    /**
        Creates a new instance of the Electrum struct

        ## Arguments
        * `url` - The url of the electrum server to connect to.
                  If None, a public electrum server will be used.
        * `network` - The network of the electrum server. Only used to cross check on creation
    */
    pub fn new(url: &Option<String>, network: &Network) -> Result<Self, ElectrumErr> {
        let client_constructor = match url {
            Some(x) => Client::new(&x),
            None => Client::new("tcp://electrum.blockstream.info:60001")
        };

        match client_constructor {
            Ok(client) => {
                let client = Self { client };
                if network == &client.server_network()? { return Ok(client) }
                else { return Err(ElectrumErr::FailedToConnect) }
            },
            Err(_) => return Err(ElectrumErr::FailedToConnect)
        }
    }

    /**
        Internal method to check the client network and check if the client can connect to the server.
    */
    fn server_network(&self) -> Result<Network, ElectrumErr> {
        let genesis_block_h = match self.client.server_features() {
            Ok(x) => x.genesis_hash.to_vec(),
            Err(_) => return Err(ElectrumErr::FailedToConnect)
        };

        //Mainnet genesis hash
        if genesis_block_h == decode_02x("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f") { return Ok(Network::Bitcoin) }
        //Testnet genesis hash
        else if genesis_block_h == decode_02x("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943") { return Ok(Network::Testnet)  }
        
        //Unknown genesis hash
        else { return Err(ElectrumErr::FailedToConnect) }
    }

    /**
        Gets a tx given a txid string
    */
    fn get_tx(&self, txid: &str) -> Result<electrum_client::bitcoin::Transaction, ElectrumErr> {
        let txid = electrum_client::bitcoin::Txid::from_hash(electrum_client::bitcoin::hashes::sha256d::Hash::from_hex(txid).unwrap());
        let tx = match self.client.transaction_get(&txid) {
            Ok(x) => x,
            Err(_) => return Err(ElectrumErr::FailedToGet())
        };

        Ok(tx)
    }

    /**
        Gets a script pubkey given a txid and output index
    */
    pub fn get_input_script_pubkey(&self, txid: &str, vout: usize) -> Result<Vec<u8>, ElectrumErr> {
        let tx = self.get_tx(txid)?;
        let vout = vout as usize;

        if vout > tx.output.len() {
            return Err(ElectrumErr::MissingVout())
        }

        Ok(tx.output[vout].script_pubkey.clone().into_bytes())
    }

    /**
        Gets the output value given a txid and output index
    */
    pub fn get_input_value(&self, txid: &str, vout: usize) -> Result<u64, ElectrumErr> {
        let tx = self.get_tx(txid)?;

        if vout > tx.output.len() {
            return Err(ElectrumErr::MissingVout())
        }

        Ok(tx.output[vout].value.clone())
    }
}