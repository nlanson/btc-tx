/*
    This library aims to implement Bitcoin transactions.

    Please do not broadcast transactions created with this
    library unless you are 100% confident.

    References:
        - The Bitcoin Book (https://github.com/bitcoinbook/bitcoinbook)
        - Learn me a bitcoin (https://learnmeabitcoin.com/technical/)


    Todo:
        - Transaction Builder (See bitcoinjs-lib TransactionBuilder)
                - Checks on various elements (eg network, value)
                - Implement P2WSH input signing
                        > This will involve creating the p2wsh pipe method and modifying the segwit hashpreimage method
                           to accomadate for script_code for P2WSH as defined in BIP 143
                
    
        - Sig module
                - Verify txns with sighashes
        
        - Unit tests
            > Create unit tests for implemented transaction types using already broadcasted data in examples/main.rs
*/

//Modules
pub mod signature;
pub mod tx;
pub mod util;
pub mod api;
pub mod hash;

//Dependencies
use btc_keyaddress::prelude::*;
use bs58;
use sha2::{Sha256, Digest};
pub use secp256k1::{
    PublicKey,
    Secp256k1,
    SecretKey,
    Signature,
    Message,
    SerializedSignature
};
use bitcoin_bech32::{
    WitnessProgram, u5,
    constants::Network
};
