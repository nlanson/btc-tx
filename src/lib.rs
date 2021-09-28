/*
    This library aims to implement Bitcoin transactions.

    Please do not broadcast transactions created with this
    library unless you are 100% confident.

    References:
        - The Bitcoin Book (https://github.com/bitcoinbook/bitcoinbook)
        - Learn me a bitcoin (https://learnmeabitcoin.com/technical/)


    Todo:
        - Transaction Builder (See bitcoinjs-lib TransactionBuilder)
                - General clean up (Use of Err Enums instead of panic, split up, etc...)
                - Modify what part of a transaction is being signed based on the sighash provided
                - Implement the creation of outputs that are not P2PKH
                - Implement the use of inputs that are not P2PKH
    
        - Sig module
                - Verify txns with sighashes
*/

//Modules
pub mod signature;
pub mod tx;
pub mod util;
pub mod api;
pub mod hash;

//Dependencies
pub use btc_keyaddress::prelude::*;
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
