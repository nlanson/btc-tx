/*
    The examples with broadcasted TXs can be used in unit tests
*/

use btc_tx::*;
use btc_tx::{
    util::{
        serialize::Serialize,
        Network
    },
    tx::{
        SigningData,
        SigHash,
        TxBuilder,
        Tx,
        Script
    }
};

use btc_keyaddress::prelude::*;
use btc_keyaddress::key::PrivKey as PrivKey;
use btc_keyaddress::key::PubKey as PubKey;
use btc_keyaddress::prelude::Script as RedeemScript;

fn main() {
    spend_p2sh_p2wpkh();
}

fn spend_p2sh_p2wpkh() {
    let mut txb = TxBuilder::new(Network::Testnet);
    txb.add_input("3d0b0b9ccc50efa160ac4d69be18b1c4f4b72c4aed55645c0fb7edfe5dc7e7c7", 0).unwrap();
    txb.add_output("2NChp1fpJkEn5vRjXK6gKPgwbBi3TAVvTKX", 95000).unwrap();

    let key = PrivKey::from_wif("cQTQNYrAbwZN6RDuxL4C9WMH8JBNfVPKVwFJtVqCksgjmHTWdtCR").unwrap();
    let signing_data = SigningData::new(
        vec![key.clone()],
        Some(Script::p2sh_p2wpkh_redeem_script(&key))
    );
    txb.sign_input(0, &signing_data, SigHash::ALL).unwrap();
    let tx: Tx = txb.build().unwrap();

    println!("{}", encode_02x(&tx.serialize().unwrap()))
}