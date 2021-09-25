/*
    This library aims to implement Bitcoin transactions.

    Please do not broadcast transactions created with this
    library unless you are 100% confident.

    References:
        - The Bitcoin Book (https://github.com/bitcoinbook/bitcoinbook)
        - Learn me a bitcoin (https://learnmeabitcoin.com/technical/)


    Todo:
        - Sig module
                - Sign messages with private key
                - Verify signatures with public key
                - Serialize signatures with DER
                - Verify txns with sighashes

        - Creating transactions
                - Data to use? (Could create dummy UTXOs or use Test net)
                - Creating tx's with empty* scriptSigs to sign
                - Creating locking and unlocking scripts
*/

//Modules
pub mod sig;
pub mod tx;
pub mod util;

//Dependencies
use secp256k1::{
    PublicKey,
    Secp256k1,
    SecretKey,
    Signature,
    Message
};
use secp256k1::rand::rngs::OsRng as SecpOsRng;
use rand::rngs::OsRng;