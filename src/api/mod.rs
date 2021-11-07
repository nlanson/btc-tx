/*
    API module to make http requests to the ElectrumX Server.
    A custom server can be specified or a default one will be used. (blockstream)

    Public electrum servers sourced from https://1209k.com/bitcoin-eye/ele.php?chain=btc

    Todo:
        - TOR configuration
            > Determine which port to use for SOCKS interface (9150 with browser or 9050 standalone).
              This should be determined on a case by case basis where the code will test both ports and 
              use the available port and fail if both fail.
            > Figure out how to install and run a TOR socks proxy locally wihout the browser.
            > Unit tests for Testnet and Mainnet electrum requests.
*/

use bitcoin_hashes::hex::FromHex;
use crate::{
    Client, 
    ElectrumApi,
    ConfigBuilder,
    Socks5Config,
    util::bytes::decode_02x,
    util::bytes::encode_02x,
    util::Network
};

pub struct Electrum {
    client: Client
}

#[derive(Debug)]
pub enum ElectrumErr {
    FailedToConnect,
    UnknownGenesis(String),
    FailedToGet,
    MissingVout(u32),
    NetworkMismatch,
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
        //Create the client
        let client: Result<_, _> = match url {
            //If a url is provided...
            Some(x) => {
                if x.contains(".onion") { 
                    //If the provided url is an onion address...
                    let possible_proxies = vec![
                        "127.0.0.1:9150",  //TOR Browser Bundle
                        "127.0.0.1:9050"   //Standalone TOR
                    ];

                    //Test each of the possible proxies
                    let mut i = 0;
                    loop {
                        let proxy = Socks5Config::new(possible_proxies[i]);
                        let config = ConfigBuilder::new().socks5(Some(proxy)).unwrap().build();
                        let c = Client::from_config(&x, config.clone());
                        match c {
                            //If client successfully connects using a proxy, return the client
                            Ok(_) => break c,
                            
                            //If the proxy fails, try the next one or return an error if there are no more.
                            Err(_) => { 
                                i+=1; 
                                if i >= possible_proxies.len() { return Err(ElectrumErr::FailedToConnect); } 
                                continue;
                            }
                        }
                    }
                } else {
                    //If the provided url is not an onion address...
                    Client::new(&x)
                }
            },

            //If no url is provided, use a public electrum server based on the network specified.
            None => match network {
                    Network::Bitcoin => Client::new("tcp://electrum.blockstream.info:50001"),
                    Network::Testnet => Client::new("tcp://electrum.blockstream.info:60001")
            }
        };

        //Check that the client constructed successfully.
        let client = match client {
            Ok(x) => x,
            Err(_) => return Err(ElectrumErr::FailedToConnect)
        };

        //Check that the client is connected to the right network.
        let client = Self { client };
        let detected_network = client.server_network()?;
        if network == &detected_network { return Ok(client) }
        else { return Err(ElectrumErr::NetworkMismatch) }
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
        else { return Err(ElectrumErr::UnknownGenesis(encode_02x(&genesis_block_h))) }
    }

    /**
        Gets a tx given a txid string
    */
    fn get_tx(&self, txid: &str) -> Result<electrum_client::bitcoin::Transaction, ElectrumErr> {
        let txid = electrum_client::bitcoin::Txid::from_hash(electrum_client::bitcoin::hashes::sha256d::Hash::from_hex(txid).unwrap());
        let tx = match self.client.transaction_get(&txid) {
            Ok(x) => x,
            Err(_) => return Err(ElectrumErr::FailedToGet)
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
            return Err(ElectrumErr::MissingVout(vout as u32));
        }

        Ok(tx.output[vout].script_pubkey.clone().into_bytes())
    }

    /**
        Gets the output value given a txid and output index
    */
    pub fn get_input_value(&self, txid: &str, vout: usize) -> Result<u64, ElectrumErr> {
        let tx = self.get_tx(txid)?;

        if vout > tx.output.len() {
            return Err(ElectrumErr::MissingVout(vout as u32))
        }

        Ok(tx.output[vout].value.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_electrum_mainnet() { Electrum::new(&None, &Network::Bitcoin).unwrap(); }

    #[test]
    fn tcp_electrum_testnet() { Electrum::new(&None, &Network::Testnet).unwrap(); }

    #[test]
    //This test requires a local SOCKS proxy to be running on port 9050 or 9150.
    //If this test fails, assume that either my Bitcoin node is down or your SOCKS proxy is not setup correctly.
    fn onion_electrum_mainnet() { Electrum::new(&Some("ews5zgbpdsgvhsf6vjoo3xektaj56e7y4jjcd6i2kddlo3vw4xf33tid.onion:50001".to_string()), &Network::Bitcoin).unwrap(); }
}