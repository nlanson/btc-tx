/*
    Module that creates and signs transactions

    Todo:
        - Implement other payment script types for input and output
        - General cleanup
        - Deny inputs or outputs based on stored sighashes
*/
use super::{
    Input, Output, Tx,
};
use btc_keyaddress::key::Key;
use crate::{
    PrivKey,
    PubKey,
    Signature,
    api,
    signature,
    util::{
        Network,
        bytes,
        serialize::Serialize,
        serialize::serialize_sig
    },
    hash
};

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
    script_sigs: Vec<Option<Vec<u8>>>, //scriptSigs are stored in this attribute
    sighashes: Vec<Option<SigHash>>   //SigHash is stored to detect if new inputs/outputs can be added
}

#[derive(Debug)]
pub enum BuilderErr {
    CannotGetScriptPubKey(String, usize),
    FailedToSerialize(),
    FailedToCreateMessageStruct(),
    UnsignedInput(usize),
    OutputIndexMissing(usize),
    InvalidInputIndex(usize)
}

impl TxBuilder {
    pub fn new(network: Network) -> Self {
        Self {
            network,
            inputs: vec![],
            outputs: vec![],
            script_sigs: vec![],
            sighashes: vec![]
        }
    }

    pub fn add_input(&mut self, txid: &str, vout: u32) {
        let txid_bytes: [u8; 32] = bytes::try_into(bytes::decode_02x(txid));
        let new_in: Input = Input::unsigned_input(txid_bytes, vout, 0xFFFFFFFF);
        self.inputs.push(new_in);
        self.script_sigs.push(None);
        self.sighashes.push(None)
    }

    pub fn add_output(&mut self, address: &str, value: u64) {
        let new_out: Output = Output::new(address, value);
        self.outputs.push(new_out);
    }

    pub fn sign_input(&mut self, index: usize, key: PrivKey, sighash: SigHash) -> Result<(), BuilderErr> {
        //Return an error if the given input index is larger than the total amount of inputs
        if self.inputs.len() < index {
            return Err(BuilderErr::InvalidInputIndex(index))
        }
        
        //Create a copy of the transaction
        let mut tx_copy: Tx = Tx::construct(self.inputs.clone(), self.outputs.clone(), 0);
        
        //Add the script pub key of the input currently being signed as the scriptSig
        tx_copy.inputs[index].scriptSig = Self::get_input_script_pub_key(&self, index)?;
        tx_copy.inputs[index].scriptSig_size = tx_copy.inputs[index].scriptSig.len() as u64;

        //Based on the provided SigHash, modify the transaction data
        Self::modify_tx_copy(&mut tx_copy, &sighash, index)?;

        //Sign the modified tx_copy
        let signature: Signature = Self::create_signature(&tx_copy, &sighash, &key)?;
        
        //Construct the scriptSig for the input
        let script_sig: Vec<u8> = Self::construct_script_sig(&self, index, &signature, &sighash, &key)?;

        //Store the scriptSig and sighash to use later
        self.script_sigs[index] = Some(script_sig);
        self.sighashes[index] = Some(sighash);


        
        Ok(())
    }

    /**
        Get the scriptPubKey for the input being signed
    */
    fn get_input_script_pub_key(&self, index: usize) -> Result<Vec<u8>,BuilderErr> {
        let rpc = api::JsonRPC::new(&self.network);
        let input_spkhex: Vec<u8> = match rpc.get_input_script_pub_key_hex(&bytes::encode_02x(&self.inputs[index].txid), self.inputs[index].vout) {
            Ok(x) => bytes::decode_02x(&x),
            Err(_) => return Err(BuilderErr::CannotGetScriptPubKey(bytes::encode_02x(&self.inputs[index].txid), index))
        };

        Ok(input_spkhex)
    }

    /**
        Modifies the tx to be signed based on the sighash
    */
    fn modify_tx_copy(tx_copy: &mut Tx, sighash: &SigHash, index: usize) -> Result<(), BuilderErr> {
        match sighash {
            SigHash::ALL => { 
                /*No need to modify txdata for sighash_all*/ 
            },
            SigHash::NONE => {
                //Remove all outputs and set output count to 0
                tx_copy.output_count = 0x00;
                tx_copy.outputs = vec![];
            },
            SigHash::SINGLE => {
                //Remove all outputs apart from the output at the same index as the input being signed
                if tx_copy.outputs.len() > index {
                    tx_copy.outputs = vec![tx_copy.outputs[index].clone()];
                    tx_copy.output_count = 0x01;
                } else {
                    return Err(BuilderErr::OutputIndexMissing(index))
                }
            },
            SigHash::ALL_ANYONECANPAY => {
                //Remove all inputs apart from the one being signed
                tx_copy.inputs = vec![tx_copy.inputs[index].clone()];
                tx_copy.input_count = 0x01;
            },
            SigHash::NONE_ANYONECANPAY => {
                //Remove all inputs apart from the one being signed
                tx_copy.inputs = vec![tx_copy.inputs[index].clone()];
                tx_copy.input_count = 0x01;

                //Remove all outputs and set output count to 0
                tx_copy.output_count = 0x00;
                tx_copy.outputs = vec![];
            },
            SigHash::SINGLE_ANYONECANPAY => {
                //Remove all inputs apart from the one being signed
                tx_copy.inputs = vec![tx_copy.inputs[index].clone()];
                tx_copy.input_count = 0x01;

                //Remove all outputs apart from the output at the same index as the input being signed
                if tx_copy.outputs.len() > index {
                    tx_copy.outputs = vec![tx_copy.outputs[index].clone()];
                    tx_copy.output_count = 0x01;
                } else {
                    return Err(BuilderErr::OutputIndexMissing(index))
                }
            }
        }

        Ok(())
    }

    /**
        Sign the modified tx using the provided secret key and sighash
    */  
    fn create_signature(tx_copy: &Tx, sighash: &SigHash, key: &PrivKey) -> Result<Signature, BuilderErr> {
        //Serialize the tx_copy ready to sign
        let mut serialized_tx_copy: Vec<u8> = match tx_copy.serialize() {
            Ok(x) => x,
            Err(_) => return Err(BuilderErr::FailedToSerialize())
        };

        //Append the sig hash type to the serialized tx_copy data
        match sighash {
            SigHash::ALL => {
                let mut sighashtype = vec![0x01, 0x00, 0x00, 0x00];
                serialized_tx_copy.append(&mut sighashtype);
            },
            SigHash::NONE => {
                let mut sighashtype = vec![0x02, 0x00, 0x00, 0x00];
                serialized_tx_copy.append(&mut sighashtype);
            },
            SigHash::SINGLE => {
                let mut sighashtype = vec![0x03, 0x00, 0x00, 0x00];
                serialized_tx_copy.append(&mut sighashtype);
            },
            SigHash::ALL_ANYONECANPAY => {
                let mut sighashtype = vec![0x81, 0x00, 0x00, 0x00];
                serialized_tx_copy.append(&mut sighashtype);
            },
            SigHash::NONE_ANYONECANPAY => {
                let mut sighashtype = vec![0x82, 0x00, 0x00, 0x00];
                serialized_tx_copy.append(&mut sighashtype);
            },
            SigHash::SINGLE_ANYONECANPAY => {
                let mut sighashtype = vec![0x83, 0x00, 0x00, 0x00];
                serialized_tx_copy.append(&mut sighashtype);
            }
        }

        //Hash the serialized tx_copy and create the message struct from the hash
        let msg = match signature::new_msg(&hash::sha256d(&serialized_tx_copy)) {
            Ok(x) => x,
            Err(_) => return Err(BuilderErr::FailedToCreateMessageStruct())
        };

        //Sign the message and return the signature
        Ok(signature::sign(&msg, &key.raw()))
    }

    /**
        Construct the scriptSig for the input being signed based on the script pub key of the input,
        signature, sighash and private key used to sign the input.
    */
    fn construct_script_sig(&self, index: usize, signature: &Signature, sighash: &SigHash, key: &PrivKey) -> Result<Vec<u8>, BuilderErr> {
        let script_sig: Vec<u8> = match Self::get_input_script_pub_key(&self, index)?[0] {
            //P2PKH ScriptSigs
            //OP_DUP
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

            //ScriptSigs other than P2PKH inputs are not implemented yet
            _ => unimplemented!()
        };

        Ok(script_sig)
    }

    pub fn build(&self) -> Result<Tx, BuilderErr> {
        let version: u32 = 1;
        let input_count: usize = self.inputs.len();
        let output_count: usize = self.outputs.len();
        let locktime: u32 = 0x00000000;

        //Loop over each input and its stored scriptSig if it exists
        let mut inputs: Vec<Input> = vec![];
        for i in 0..self.inputs.len() {
            match &self.script_sigs[i] {
                Some(x) => {
                    let mut input = self.inputs[i].clone();
                    input.scriptSig = x.clone();
                    input.scriptSig_size = input.scriptSig.len() as u64;

                    inputs.push(input);
                },
                
                //If input is not signed, return an error
                None => return Err(BuilderErr::UnsignedInput(i))
            }
        }

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