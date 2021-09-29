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
                      > Detect whether there is a SegWit input. If there is, serialize the 
                        transaction with the witness marker, flag and witness array.
                      > Place scriptSigs of SegWit inputs in the appropriate position in the Witness Array
                      > If an input is non-SegWit, keep Witness array value at position as 0x00
    
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
