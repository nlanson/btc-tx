/*
    Module that creates and signs transactions

    Todo:
        - Modify txCopy based on provided sighash when signing transactions
        - Implement other payment script types for input and output
        - General cleanup
*/
use super::{
    Input, Output, Tx,
};

use crate::{
    PrivKey,
    PubKey,
    SecretKey,
    Signature,
    api,
    signature,
    util::{
        Network,
        Script,
        bytes,
        script,
        serialize::Serialize,
        serialize::serialize_sig
    },
    hash
};
use btc_keyaddress::key::Key;
#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
pub enum SigHash {
    ALL,                 //All inputs and outputs are committed. 
    NONE,                //All inputs are committed. No outputs.
    SINGLE,              //All inputs and the output with the same index as the input being signed are committed.
    ALL_ANYONECANPAY,    //Current input and all outputs are committed.
    NONE_ANYONECANPAY,   //Current input and no outputs are committed.
    SINGLE_ANYONECANPAY  //Current input and output with the same index are committed.
}

#[derive(Debug)]
pub struct TxBuilder {
    network: Network,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    signatures: Vec<Option<Vec<u8>>>,
    sighashes: Vec<Option<SigHash>>
}

#[derive(Debug)]
pub enum BuilderErr {

}

impl TxBuilder {
    pub fn new(network: Network) -> Self {
        Self {
            network,
            inputs: vec![],
            outputs: vec![],
            signatures: vec![],
            sighashes: vec![]
        }
    }

    pub fn add_input(&mut self, txid: &str, vout: u32) {
        let txid_bytes: [u8; 32] = bytes::try_into(bytes::decode_02x(txid));
        let new_in: Input = Input::unsigned_input(txid_bytes, vout, 0xFFFFFFFF);
        self.inputs.push(new_in);
        self.signatures.push(None);
        self.sighashes.push(None)
    }

    pub fn add_output(&mut self, address: &str, value: u64) {
        let new_out: Output = Output::new(address, value);
        self.outputs.push(new_out);
    }

    pub fn sign_input(&mut self, index: usize, key: PrivKey, sighash: SigHash) -> Result<(), BuilderErr> {
        // Sign the input at the given index with the given key and given sighash.
        //  - Depending on the selected sigHash, modify the transaction as needed to construct the bytes to sign.
        //  - Sign the TxData and use the signature and pub key to construct the correct scriptSig OP_CODES based on the 
        //     locking script attached to the input

        let mut txCopy: Tx = Tx::construct(self.inputs.clone(), self.outputs.clone(), 0);
        
        //Add the script pub key of the input currently being signed as the scriptSig
        let rpc = api::JsonRPC::new(&self.network);
        let input_spkhex: Vec<u8> = match rpc.get_input_script_pub_key_hex(&bytes::encode_02x(&self.inputs[index].txid), self.inputs[index].vout) {
            Ok(x) => bytes::decode_02x(&x),
            Err(x) => panic!("Cannot get input's pub key hash")
        };
        txCopy.inputs[index].scriptSig = input_spkhex.clone();
        txCopy.inputs[index].scriptSig_size = txCopy.inputs[index].scriptSig.len() as u64;

        //Based on the provided SigHash, modify the transaction data
        //Only SigHash_ALL is implemented for now
        match sighash {
            SigHash::ALL => { /*No need to modify txdata for sighash_all*/ },

            //Other sighash types are not yet implemented
            _ => unimplemented!()
        }

        let mut serialized_txCopy: Vec<u8> = match txCopy.serialize() {
            Ok(x) => x,
            Err(x) => panic!("Failed to serialize txCopy")
        };
        //Append the sig hash type to the serialized txCopy data
        //Only SigHash_ALL is implemented for now.
        match sighash {
            SigHash::ALL => {
                let mut sighashtype = vec![0x01, 0x00, 0x00, 0x00];
                serialized_txCopy.append(&mut sighashtype);
            },
            
            //Other sighash types are not yet implemented
            _ => unimplemented!()
        }

        //Sign the tx data
        let msg = match signature::new_msg(&hash::sha256d(&serialized_txCopy)) {
            Ok(x) => x,
            Err(x) => panic!("Could not create MessageStruct from serialized txcopy")
        };
        let signature: Signature = signature::sign(&msg, &key.raw());

        
        //Construct the scriptSig here based on the pub key hash
        let scriptSig: Vec<u8> = match input_spkhex[0] {
            //OP_DUP (P2PKH)
            0x76 => {
                let mut v: Vec<u8> = vec![];
                let ss = serialize_sig(&signature);
                let pk: PubKey = PubKey::from_priv_key(&key);
                v.push((ss.len()+1) as u8);                   //Length of Sig
                v.append(&mut ss.to_vec());                   //Serialized Sig
                match sighash {                               //SigHash
                    SigHash::ALL => v.push(0x01),
                    SigHash::NONE => v.push(0x02),
                    SigHash::SINGLE => v.push(0x03),
                    SigHash::ALL_ANYONECANPAY => v.push(0x81),
                    SigHash::NONE_ANYONECANPAY => v.push(0x82),
                    SigHash::SINGLE_ANYONECANPAY => v.push(0x83)
                }
                v.push(pk.as_bytes::<33>().len() as u8);      //Length of PK
                v.append(&mut pk.as_bytes::<33>().to_vec());  //PK bytes
                
                v
            },

            //Input types other than P2PKH inputs are not implemented
            _ => unimplemented!()
        };

        //Store the scriptSig and sighash to use later
        self.signatures[index] = Some(scriptSig);
        self.sighashes[index] = Some(sighash);


        
        Ok(())
    }

    pub fn build(&self) -> Result<Tx, BuilderErr> {
        let version: u32 = 1;
        let input_count: usize = self.inputs.len();
        let output_count: usize = self.outputs.len();
        let locktime: u32 = 0x00000000;
        let inputs: Vec<Input> = self.inputs.iter().enumerate().map(|(i, x)| {
            let mut input = x.clone();
            input.scriptSig = match &self.signatures[i] {
                Some(x) => x.clone(),
                None => panic!("input not signed at index {}", i)
            };
            input.scriptSig_size = input.scriptSig.len() as u64;

            input
        }).collect();

        Ok(Tx {
            version,
            input_count: input_count as u64,
            inputs,
            output_count: output_count as u64,
            outputs: self.outputs.clone(),
            locktime
        })
    }
}