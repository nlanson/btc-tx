#[allow(non_snake_case)]
/*
    Input struct representing UTXOs to be consumed in
    a transaction.
*/

use crate::{
    util::bytes::{
        decode_02x as d02,
        encode_02x as e02
    },
    util::serialize::{
        Serialize as SerializeTrait,
        SerializationError
    },
    util::varint::VarInt as VarInt,
};

use super::{
    Tx
};

#[derive(Debug, Clone)]
pub struct Input {
    pub txid: [u8; 32],         //Pointer to the tx containing UTXO to be spent    (little endian)
    pub vout: u32,              //The index number of the UTXO in the referred tx  (little endian)
    pub scriptSig_size: u64,    //To be converted into a VarInt for serialization
    pub scriptSig: Vec<u8>,     //Unlocking script opcodes   
    pub sequence: u32,          //4byte (32bit) integer                            (little endian)
    pub segwit: bool
}

impl SerializeTrait for Input {
    fn serialize(&self) -> Result<Vec<u8>, SerializationError> {
        let mut bytes: Vec<u8> = vec![];
        
        let mut txid_bytes = self.txid.to_vec();
        txid_bytes.reverse();
        let mut vout_bytes = self.vout.to_le_bytes().to_vec();
        let mut sg_size_varint = match VarInt::from_usize(self.scriptSig.len()) {
            Ok(x) => x,
            Err(x) => return Err(SerializationError::VarIntErr(self.scriptSig.len()))
        };
        let mut sg = self.scriptSig.clone();
        let mut seq_bytes = self.sequence.to_le_bytes().to_vec();


        bytes.append(&mut txid_bytes);
        bytes.append(&mut vout_bytes);
        bytes.append(&mut sg_size_varint);
        bytes.append(&mut sg);
        bytes.append(&mut seq_bytes);

        Ok(bytes)
    }
}

impl Input {
    pub fn unsigned_input(
        txid: [u8; 32],
        vout: u32,
        sequence: u32
    ) -> Self {
        Self {
            txid,
            vout,
            scriptSig_size: 0x01,  //Unsure if this should be 0x00 or 0x01 for inputs that aren't being signed.
            scriptSig: vec![0x00],
            sequence,
            segwit: false
        }
    }
}