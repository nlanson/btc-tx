/*
    This library aims to implement Bitcoin transactions.

    Please do not broadcast transactions created with this
    library unless you are 100% confident.

    References:
        - The Bitcoin Book (https://github.com/bitcoinbook/bitcoinbook)
        - Learn me a bitcoin (https://learnmeabitcoin.com/technical/)


    Todo:
        - Transaction Builder (See bitcoinjs-lib TransactionBuilder)              
               - General cleanup and refactoring (Looking for a BIG cleanup and redesign of the library)
               - Unit tests for internal methods
               - Signing Taproot inputs (Control blocks, annex and etc...)
        
        - Documentation
*/

//Modules
pub mod signature;
pub mod tx;
pub mod util;
pub mod api;
pub mod hash;
pub mod prelude;

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
use electrum_client::{
    Client,
    ElectrumApi,
    ConfigBuilder,
    Socks5Config
};
