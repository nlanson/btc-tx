/*
    This library aims to implement Bitcoin transactions.

    Please do not broadcast transactions created with this
    library unless you are 100% confident.

    References:
        - The Bitcoin Book (https://github.com/bitcoinbook/bitcoinbook)
        - Learn me a bitcoin (https://learnmeabitcoin.com/technical/)


    Todo:
        - Transaction Builder (See bitcoinjs-lib TransactionBuilder)
                - Struct to aid the creation of a transaction.
                - Ability to sign transactions independently with a .sign(index) method.
                   This will take in the index of the input being signed and the key to sign the input with
                   as well as the sighash flag to indicate so the builder can detect later when new inputs/ouputs
                   are being added.
                - Ability to add inputs from txid and out index
                - Ability to add outputs with recipient address and amount
                - Ability detect the sigHash in a signed input and deny new inputs or outputs based on already signed inputs.
    
        - Sig module
                - Verify txns with sighashes

        - Serialization module
                - Serialize inputs, outputs and transactions                      ~~[high priority]~~
                - Serialize integers into byte arrays (big or little endian)
                - Serialize inputs, outputs, signatures and entire transactions.

        - Script module to easily construct relevant locking and unlocking scripts   ~~[high priority]~~

        - Create new outputs (P2PKH only for now) in the output module using scripts from the script module  ~~[high priority]~~
        
        - Hash module
                - Create wrapper functions around crypto-rs library hash methods
                   for hashes used in the creation of transactions (double sha256)

        - Creating transactions
                - Creating tx's with empty* scriptSigs to sign
                - Creating locking and unlocking scripts
                - Start by making transactions that take in 1 input.
                   Then exapand to multiple inputs.
                   Ref (How to sign a Tx with multiple inputs with sighash all) https://bitcoin.stackexchange.com/questions/41209/how-to-sign-a-transaction-with-multiple-inputs/88281?noredirect=1#comment101253_88281
                - Write code to create transactions given a UTXO(s), receipient pub key hash, and amount to send.
                   This shouldn't be too hard. It will involve:
                        - Creating the blanket tx with the inputs and ouputs. However, the scriptSig of the inputs will be empty.
                        - Sign each input with the priv key needed to unlock it by putting the input's pub key hash in the script sig.
                        - Start by using the SigHash All (can do other sighashes later)
                        - Once all inputs are signed, serialize transaction.
                        - Ref (How to redeem a basic Tx) https://bitcoin.stackexchange.com/questions/3374/how-to-redeem-a-basic-tx
*/

//Modules
pub mod signature;
pub mod tx;
pub mod util;
pub mod api;

//Dependencies
pub use secp256k1::{
    PublicKey,
    Secp256k1,
    SecretKey,
    Signature,
    Message,
    SerializedSignature
};
