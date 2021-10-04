/*
    Module that makes writing script easier.
*/
use btc_keyaddress::key::Key;
use crate::{
    util::{
        bech32,
        serialize::serialize_sig,
        varint::VarInt
    },
    Signature,
    tx::{
        SigHash,
        SigningData
    },
    PrivKey, PubKey
};

#[derive(Debug, Clone)]
pub enum ScriptType {
    P2PKH,
    P2SH,
    P2WPKH,
    P2WSH
}


#[allow(non_camel_case_types)]
pub enum ScriptCodes {
    //Null Data / False
    OP_0 = 0x00,
    
    //P2PKH Codes
    OP_DUP = 0x76,
    OP_HASH160 = 0xA9,
    OP_EQUALVERIFY = 0x88,
    OP_CHECKSIG = 0xAC,

    //P2SH Codes
    OP_EQUAL = 0x87
}

pub enum ScriptErr {
    UnknownScript(),
    MissingScript()
}

#[derive(Debug, Clone)]
pub struct Script {
    pub code: Vec<u8>
}

impl Script {
    pub fn new(code: Vec<u8>) -> Self {
        Self {
            code
        }
    }

    pub fn empty() -> Self {
        Self::new(vec![0x00])
    }
    
    pub fn len(&self) -> u64 {
        self.code.len() as u64
    }

    /**
        Creates a P2PKH locking script from a pub key hash address
    */
    pub fn p2pkh_locking(address: &str) -> Self {
        let mut unlock_script: Vec<u8> = vec![];
        unlock_script.push(ScriptCodes::OP_DUP as u8);
        unlock_script.push(ScriptCodes::OP_HASH160 as u8);
        unlock_script.push(0x14); //Length of the PubKey Hash to follow
        let mut address_bytes: Vec<u8> = match bs58::decode(address).into_vec() {
            Ok(x) => {
                x[1..x.len()-4].to_vec()
            },
            Err(_) => panic!("cannot decode recepient address")
        };
        unlock_script.append(&mut &mut address_bytes);
        unlock_script.push(ScriptCodes::OP_EQUALVERIFY as u8);
        unlock_script.push(ScriptCodes::OP_CHECKSIG as u8);
        
        Self::new(unlock_script)
    }

    /**
        Create a P2SH locking script from an script hash address
    */
    pub fn p2sh_locking(address: &str) -> Self {
        let mut locking_script: Vec<u8> = vec![];
                locking_script.push(ScriptCodes::OP_HASH160 as u8);
                let mut script_hash_bytes: Vec<u8> = match bs58::decode(address).into_vec() {
                    Ok(x) => {
                        x[1..x.len()-4].to_vec()
                    },
                    Err(_) => panic!("cannot decode redeeming script")
                };
                locking_script.append(&mut VarInt::from_usize(script_hash_bytes.len()).unwrap());
                locking_script.append(&mut script_hash_bytes);
                locking_script.push(ScriptCodes::OP_EQUAL as u8);
                
                Self::new(locking_script)
    }

    /**
        Create a SegWit locking script from a Bech32 address
    */
    pub fn segwit_locking(address: &str) -> Self {
        let mut unlocking_script: Vec<u8> = vec![];
        let mut spk: Vec<u8> = bech32::decode(address);
        unlocking_script.append(&mut spk);
        
        Self::new(unlocking_script)
    }

    /**
        Create a PubKeyHash unlocking script for P2PKH and P2WPKH inputs
    */
    pub fn pkh_unlocking(signature: &Signature, signing_key: &PrivKey, sighash: &SigHash) -> Self {
        let mut unlocking_script: Vec<u8> = vec![];

        //Set values
        let ss = serialize_sig(&signature);
        let pk: PubKey = PubKey::from_priv_key(&signing_key);
        let shb = match sighash {
            SigHash::ALL => 0x01,
            SigHash::NONE => 0x02,
            SigHash::SINGLE => 0x03,
            SigHash::ALL_ANYONECANPAY => 0x81,
            SigHash::NONE_ANYONECANPAY => 0x82,
            SigHash::SINGLE_ANYONECANPAY => 0x83
        };

        //Push values
        unlocking_script.push((ss.len()+1) as u8);                   //Length of Sig
        unlocking_script.append(&mut ss.to_vec());                   //Serialized Sig
        unlocking_script.push(shb);                                  //Sighash Byte
        unlocking_script.push(pk.as_bytes::<33>().len() as u8);      //Length of PK
        unlocking_script.append(&mut pk.as_bytes::<33>().to_vec());  //PK bytes
        
        Self::new(unlocking_script)
    }

    pub fn determine_type(&self) -> Result<ScriptType, ScriptErr> {
        let input_script_type: ScriptType = match self.code[0] {
            0x76 => ScriptType::P2PKH,
            0xA9 => ScriptType::P2SH,
            //Segwit Version 0
            0x00 => {
                match self.code[1] {
                    0x14 => ScriptType::P2WPKH,
                    0x20 => ScriptType::P2WSH,
                    _ => return Err(ScriptErr::UnknownScript())
                } 
            },
            _ => return Err(ScriptErr::UnknownScript())
        };

        Ok(input_script_type)
    }

    /**
        Wrapper around btc-keyaddress lib to create M-of-N multisig locking scripts
        to present when signing P2SH inputs.
    */
    pub fn p2sh_multisig_locking(m: u8, n: u8, keys: &Vec<PrivKey>) -> Self {
        let script = match btc_keyaddress::prelude::Script::multisig(m, n, keys) {
            Ok(x) => x,
            Err(_) => panic!("Failed to create p2SH MultiSig redeem script")
        };

        Self::new(script.script)
    }

    /**
        Returns the scriptSig for a P2SH multisig input
    */
    pub fn p2sh_multisig_unlocking(signatures: &Vec<Signature>, signing_data: &SigningData, sighash: &SigHash) -> Result<Self, ScriptErr> {
        let mut redeem_script: Script = match signing_data.script.clone() {
            Some(x) => x,
            None => return Err(ScriptErr::MissingScript())
        };
        
        let mut script: Vec<u8> = vec![];
        script.push(0x00); //Push OP_0 first with multisig redeem script due to a bug in Bitcoin core
        for i in 0..signatures.len() {
            //Append each signature to the script.
            //If none are present this loop will not be entered
            let mut serialized_signature = serialize_sig(&signatures[i]).to_vec();
            script.append(&mut VarInt::from_usize(serialized_signature.len() + 1).unwrap());
            script.append(&mut serialized_signature);
            script.push(sighash.clone() as u8);
        }
        
        //Append the redeem script
        //If the redeem script is too long to use push_bytes op code,
        //use the push data opcode.
        if redeem_script.code.len() > 0x4b {
            script.push(0x4c); //push data 1 bytes
        }
        script.push(redeem_script.code.len() as u8);


        script.append(&mut redeem_script.code);

        Ok(Script::new(script))
    }

}