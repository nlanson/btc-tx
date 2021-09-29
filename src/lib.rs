/*
    This library aims to implement Bitcoin transactions.

    Please do not broadcast transactions created with this
    library unless you are 100% confident.

    References:
        - The Bitcoin Book (https://github.com/bitcoinbook/bitcoinbook)
        - Learn me a bitcoin (https://learnmeabitcoin.com/technical/)


    Todo:
        - Transaction Builder (See bitcoinjs-lib TransactionBuilder)
                - Possibly split up builder based on input/output type
                - Implementing P2SH inputs:
                      > When signing a P2SH input, the redeemScript needs to be provided
                - Implementing SegWit
                      > Signing SegWit Inputs needs to follow BIP-143 specification
    
        - Sig module
                - Verify txns with sighashes
        
        - Unit tests
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
