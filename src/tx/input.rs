#[allow(non_snake_case)]
/*
    Input struct representing UTXOs to be consumed in
    a transaction.
*/

use crate::{
    SecretKey,
    util::{
        encode_02x as e02,
        decode_02x as d02
    }
};

use super::{
    Tx
};

#[derive(Debug, Clone)]
pub struct Input {
    txid: [u8; 32],         //Pointer to the tx containing UTXO to be spent    (little endian)
    vout: u32,              //The index number of the UTXO in the referred tx  (little endian)
    scriptSig_size: u64,    //To be converted into a VarInt for serialization
    scriptSig: Vec<u8>,     //Unlocking script opcodes   
    sequence: u32,          //4byte (32bit) integer                            (little endian)
    secret_key: SecretKey   //The private key that can unlock the output
}

impl Input {
    pub fn unsigned_input(
        txid: [u8; 32],
        vout: u32,
        sequence: u32,
        sk: &SecretKey
    ) -> Self {
        Self {
            txid,
            vout,
            scriptSig_size: 0x00,  //Unsure if this should be 0x00 or 0x01 for inputs that aren't being signed.
            scriptSig: vec![0x00],
            sequence,
            secret_key: sk.clone()
        }
    }

    pub fn sign_input(txCopy: &Tx, vin_index: u64) -> Input {
        let mut txCopy = txCopy.clone();

        /*
            Copy the pubKeyHash of the input being redeemed into the current input's scriptSig field
            
            This should be done differently for each and every tx using the Bitcoin json RPC but since
            I do not have my own node yet, I am using dummy data from the Bitcoin test network.
        */
        txCopy.inputs[vin_index as usize].scriptSig = d02("76a91482c0b4af9fd90ed137194b4946b0b86d44a47f8c88ac");
        txCopy.inputs[vin_index as usize].scriptSig_size = txCopy.inputs[vin_index as usize].scriptSig.len() as u64;

        /*
            From here, the transaction needs to be serialized and hash code type appended.
            Once serialized, double sha256 the serialized transaction and sign it with the
            private key that unlocks the input.

            This signature will then have the SIGHASH_ALL byte appended to it.
            Then we can construct the final scriptSig by concatenating the
                - One byte opcode representing the length of the serialized signature
                - The actual serialized signature
                - One byte opcode representing the length of the public key
                - The actual public key
            
            Create a new input that is identical to the one we were working on but with the 
            scriptSig and scriptSigSize replaced accordingly. Return this input and it can be
            stored and collected into the final signed transaction.
        */

        todo!();
    }
}