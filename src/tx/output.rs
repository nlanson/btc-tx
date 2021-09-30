/*
    Output struct representing UTXOs to be created by
    a transaction

    Todo:
        - Construct locking scripts for non-P2PKH outputs
*/
use crate::{
    util::serialize::{
        Serialize as SerializeTrait,
        SerializationError
    },
    util::varint::VarInt as VarInt,
    tx::{
        Script
    }
};

#[derive(Debug, Clone)]
pub struct Output {
    pub value: u64,                   //Amount locked in output in Satoshis   (little endian)
    pub script_pub_key: Script        //Locking script opcodes
}

impl SerializeTrait for Output {
    fn serialize(&self) -> Result<Vec<u8>, SerializationError> {
        let mut bytes: Vec<u8> = vec![];
        let mut val_bytes: Vec<u8> = self.value.to_le_bytes().to_vec();
        let mut pksize_varint = match VarInt::from_usize(self.script_pub_key.len() as usize) {
            Ok(x) => x,
            Err(_) => return Err(SerializationError::VarIntErr(self.script_pub_key.len() as usize))
        };
        let mut spk = self.script_pub_key.clone();

        bytes.append(&mut val_bytes);
        bytes.append(&mut pksize_varint);
        bytes.append(&mut spk.code);

        Ok(bytes)
    }
}

impl Output {
    pub fn new(address: &str, value: u64) -> Self {
        //Create the scriptPubKey based on the address prefix
        let script_pub_key: Script = match address.chars().nth(0) {
            //P2PKH Addresses
            Some('1') | Some('m') | Some('n') => {
                Script::p2pkh_locking(address)
            },
            //P2SH Addresses
            Some('3') | Some('2') => {
                Script::p2sh_locking(address)
            },
            //SegWit Addresses
            Some('b') | Some('t') => {
                Script::segwit_locking(address)
            },

            _ => panic!("Invalid address detected")
        };


        Self {
            value,
            script_pub_key
        } 
    }
}