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
   //See unit tests under ../src/tx/builder/txbuilder.rs for examples
}