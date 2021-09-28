/*
    Output struct representing UTXOs to be created by
    a transaction

    Todo:
        - Construct locking scripts
*/
use crate::{
    util::serialize::{
        Serialize as SerializeTrait,
        SerializationError
    },
    util::bytes,
    util::varint::VarInt as VarInt,
    util::Script
};

#[derive(Debug, Clone)]
pub struct Output {
    pub value: u64,                   //Amount locked in output in Satoshis   (little endian)
    pub script_pub_key_size: u64,     //To be converted into a VarInt for serialization
    pub script_pub_key: Vec<u8>       //Locking script opcodes
}

impl SerializeTrait for Output {
    fn serialize(&self) -> Result<Vec<u8>, SerializationError> {
        let mut bytes: Vec<u8> = vec![];
        let mut val_bytes: Vec<u8> = self.value.to_le_bytes().to_vec();
        let mut pksize_varint = match VarInt::from_usize(self.script_pub_key.len()) {
            Ok(x) => x,
            Err(_) => return Err(SerializationError::VarIntErr(self.script_pub_key.len()))
        };
        let mut spk = self.script_pub_key.clone();

        bytes.append(&mut val_bytes);
        bytes.append(&mut pksize_varint);
        bytes.append(&mut spk);

        Ok(bytes)
    }
}

impl Output {
    pub fn new(address: &str, value: u64) -> Self {
        //Create the scriptPubKey based on the address prefix
        let script_pub_key = match address.chars().nth(0) {
            //P2PKH Address
            Some('1') | Some('m') | Some('n') => {
                let mut unlock_script: Vec<u8> = vec![];
                unlock_script.push(Script::OP_DUP as u8);
                unlock_script.push(Script::OP_HASH160 as u8);
                unlock_script.push(0x14); //Length of the PubKey Hash to follow
                //unlock_script.push(<Decoded Pubkey Hash Bytes>)
                unlock_script.push(Script::OP_EQUALVERIFY as u8);
                unlock_script.push(Script::OP_CHECKSIG as u8);
                unlock_script
            },
            //P2SH Address
            Some('3') => {
                //Pay to Script Hash Addresses are used for MultiSig and non native SegWit transactions
                todo!();
            },
            //Bech32 (SegWit)
            Some('b') => {
                //SegWit Transactions require a new field
                todo!();
            },
            _ => panic!("Invalid address detected")
        };


        Self {
            value,
            script_pub_key_size: script_pub_key.len() as u64,
            script_pub_key
        } 
    }
}