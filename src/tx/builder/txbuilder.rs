/*
    Module that creates and signs transactions

    Todo:
        - Signing P2SH, P2WSH and P2WPKH inputs
            > P2SH and P2WSH need a *special* method that will take in as many keys and a redeemScript
            > P2WPKH will need to be signed using BIP-143 specification
*/
use crate::{
    tx::{
        Input,
        Output,
        Tx,
        Script,
        ScriptType
    },
    PrivKey,
    api,
    util::{
        Network,
        bytes
    },
    tx::Witness
};
use super::pipes;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
pub enum SigHash {
    ALL = 0x01,                 //All inputs and outputs are committed. 
    NONE = 0x02,                //All inputs are committed. No outputs.
    SINGLE = 0x03,              //All inputs and the output with the same index as the input being signed are committed.
    ALL_ANYONECANPAY = 0x81,    //Current input and all outputs are committed.
    NONE_ANYONECANPAY = 0x82,   //Current input and no outputs are committed.
    SINGLE_ANYONECANPAY = 0x83  //Current input and output with the same index are committed.
}

#[derive(Debug)]
pub struct TxBuilder {
    pub network: Network,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    pub script_sigs: Vec<Option<Script>>, //scriptSigs are stored in this attribute
    pub witness: Vec<Option<Witness>>,    //witnesses are stored in this attribute
    pub sighashes: Vec<Option<SigHash>>   //SigHash is stored to detect if new inputs/outputs can be added
}

#[derive(Clone)]
pub struct SigningData {
    pub keys: Vec<PrivKey>,
    pub script: Option<Script>
}

impl SigningData {
    pub fn new(keys: Vec<PrivKey>, script: Option<Script>) -> Self {
        Self {
            keys,
            script
        }
    }
}

#[derive(Debug)]
pub enum BuilderErr {
    CannotGetScriptPubKey(String, usize),
    FailedToSerialize(),
    FailedToCreateMessageStruct(),
    UnsignedInput(usize),
    OutputIndexMissing(usize),
    InvalidInputIndex(usize),
    UnknownScriptType(),
    TxCommitted(),
    CannotGetInputValue(),
    InvalidSigningData(),
    RedeemScriptMissing()
}

impl TxBuilder {
    pub fn new(network: Network) -> Self {
        Self {
            network,
            inputs: vec![],
            outputs: vec![],
            script_sigs: vec![],
            witness: vec![],
            sighashes: vec![]
        }
    }

    /**
        Add a new input from txid and output index
    */
    pub fn add_input(&mut self, txid: &str, vout: u32) -> Result<(), BuilderErr> {
        //Check if an input has been signed that does not allow for new inputs
        for i in 0..self.sighashes.len() {
            match self.sighashes[i] {
                Some(SigHash::ALL) |
                Some(SigHash::NONE) |
                Some(SigHash::SINGLE) => return Err(BuilderErr::TxCommitted()),
                _ => { /* New input can be added */}
            }
        }
        
        let txid_bytes: [u8; 32] = bytes::try_into(bytes::decode_02x(txid));
        let new_in: Input = Input::unsigned_input(txid_bytes, vout, 0xFFFFFFFF);
        self.inputs.push(new_in);
        self.script_sigs.push(None);
        self.witness.push(None);
        self.sighashes.push(None);

        Ok(())
    }

    /**
        Add a new output with recepeint address and value
    */
    pub fn add_output(&mut self, address: &str, value: u64) -> Result<(), BuilderErr> {
        //Check if an input has been signed that does not allow for new outputs
        for i in 0..self.sighashes.len() {
            match self.sighashes[i] {
                Some(SigHash::ALL) |
                Some(SigHash::ALL_ANYONECANPAY) => return Err(BuilderErr::TxCommitted()),
                _ => { /* New input can be added */}
            }
        }
        
        let new_out: Output = Output::new(address, value);
        self.outputs.push(new_out);

        Ok(())
    }

    /**
        Sign an input in the current transaction at the given index, key and sighash
    */  
    pub fn sign_input(&mut self, index: usize, signing_data: &SigningData, sighash: SigHash) -> Result<(), BuilderErr> {
        //Return an error if the given input index is larger than the total amount of inputs
        if self.inputs.len() < index {
            return Err(BuilderErr::InvalidInputIndex(index))
        }
        
        //Create a copy of the transaction
        let tx_copy: Tx = Tx::construct(self.inputs.clone(), self.outputs.clone(), 0, false);

        //Get the unlocking script type of the input
        let script_pub_key: Script = Script::new(Self::get_input_script_pub_key(&self, index)?);
        let input_script_type: ScriptType = script_pub_key.determine_type();
        match input_script_type {
                ScriptType::P2WPKH | ScriptType::P2WSH => self.inputs[index].segwit = true,
                _ => { }
        }
        
        //Sign the input and set the script_sig based on the locking script
        match input_script_type {
            ScriptType::P2PKH => {
                //Only sign p2pkh if 1 key is provided.
                if signing_data.keys.len() == 1 {
                    pipes::p2pkh(self, &tx_copy, index, &sighash, &script_pub_key, &signing_data.keys[0])?;
                } else {
                    return Err(BuilderErr::InvalidSigningData())
                }
            },
            ScriptType::P2WPKH => {
                //Only sign p2wpkh if 1 key is provided
                if signing_data.keys.len() == 1 {
                    pipes::p2wpkh(self, &tx_copy, index, &sighash, &script_pub_key, &signing_data.keys[0])?;
                } else {
                    return Err(BuilderErr::InvalidSigningData())
                }
            },
            ScriptType::P2SH => pipes::p2sh(self, &tx_copy, index, &sighash, &signing_data)?,
            ScriptType::P2WSH => pipes::p2wsh()?,          //P2SH signing but with BIP-143
            ScriptType::NonStandard => return Err(BuilderErr::UnknownScriptType())
        }

        Ok(())
    }

    /**
        Get the scriptPubKey for the input being signed
    */
    fn get_input_script_pub_key(&self, index: usize) -> Result<Vec<u8> ,BuilderErr> {
        let rpc = api::JsonRPC::new(&self.network);
        let input_spkhex: Vec<u8> = match rpc.get_input_script_pub_key_hex(&bytes::encode_02x(&self.inputs[index].txid), self.inputs[index].vout) {
            Ok(x) => bytes::decode_02x(&x),
            Err(_) => return Err(BuilderErr::CannotGetScriptPubKey(bytes::encode_02x(&self.inputs[index].txid), index))
        };

        Ok(input_spkhex)
    }

    /**
        Take all the data in the Builder and make it into Tx that can be serialized
    */
    pub fn build(&self) -> Result<Tx, BuilderErr> {
        let version: u32 = 1;
        let input_count: usize = self.inputs.len();
        let output_count: usize = self.outputs.len();
        let locktime: u32 = 0x00000000;

        //Loop over each input and check if there is a scriptSig or witness for it
        let mut inputs: Vec<Input> = vec![];
        for i in 0..self.inputs.len() {
            if self.inputs[i].segwit { //If the input is segwit
                match &self.witness[i] {
                    Some(_) => {
                        //Remove the scriptSig
                        let mut input = self.inputs[i].clone();
                        input.scriptSig = Script::new(vec![]);
                        input.scriptSig_size = 0x00;
    
                        inputs.push(input);
                    },
                    None => return Err(BuilderErr::UnsignedInput(i))
                }
            } else { //If the input is not segwit
                match &self.script_sigs[i] {
                    Some(x) => {
                        //Put the stored scriptSig into the input
                        let mut input = self.inputs[i].clone();
                        input.scriptSig = x.clone();
                        input.scriptSig_size = input.scriptSig.len();
    
                        inputs.push(input);
                    },
                    
                    //If there is no scriptSig, check for a Witness.
                    None => return Err(BuilderErr::UnsignedInput(i))
                }
            }  
        }

        //If any of the witnesses are present in the Tx, set the SegWit data
        let mut segwit: bool = false;
        let mut flag: Option<u8> = None;
        let mut marker: Option<u8> = None;
        let mut witness: Option<Vec<Witness>> = None;
        if self.witness.iter().any(|x| {
            match x {
                Some(_) => true,
                None => false
            }
        }) {
            let mut witnesses: Vec<Witness> = vec![];
            segwit = true;
            flag = Some(0x00);
            marker = Some(0x01);


            for i in 0..self.witness.len() {
                witnesses.push(
                    match &self.witness[i] {
                    Some(x) => x.clone(),
                    None => Witness::empty()
                    }
                );
            }

            witness = Some(witnesses);
        }
        
        
        //Return the Transaction
        Ok(Tx {
            version,
            flag,
            marker,
            input_count: input_count as u64,
            inputs,
            output_count: output_count as u64,
            outputs: self.outputs.clone(),
            witness,
            locktime,
            segwit
        })
    }
}

#[cfg(test)]
mod tests {
    
}