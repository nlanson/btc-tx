/*
    The examples with broadcasted TXs can be used in unit tests
*/
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

fn main() {
    spend_p2wsh();
}

fn spend_p2wsh() {
    let mut txb = TxBuilder::new(Network::Testnet);
    txb.add_input("45336930c71d04e44361de5dcb289fc24ecaf4591db8fd1105157c7310aee441", 1).unwrap();
    txb.add_output("tb1qk0ns5zr0xgydqyyzs65sq9lrygl4336gznw4pd7cl0vhf3qww8nsymgaqm", 95000).unwrap();

    let keys = vec![
        PrivKey::from_wif("cPUFTUmN7R1vqyGetUfEv8Az5vTNAipHyCLZq8kpJS355NmB44BJ").unwrap(),
        PrivKey::from_wif("cNReSU1dagjXPo4ky99PaXbW4NobKWoppb5AVaCpjjQsJ2uRgoDe").unwrap(),
        PrivKey::from_wif("cSTgRcaiVDpG4yrsECW59wfUwYjTYsHh4UCcUhz2WatYWd18KDso").unwrap()
    ];
    let signing_data = SigningData::new(
        vec![keys[0].clone(), keys[1].clone()],
        Some(Script::multisig_locking(2, 3, &keys))
    );
    txb.sign_input(0, &signing_data, SigHash::ALL).unwrap();
    let tx: Tx = txb.build().unwrap();

    println!("{}", encode_02x(&tx.serialize().unwrap()))
}