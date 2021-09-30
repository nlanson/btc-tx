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
    Signature,
    api,
    signature,
    util::{
        Network,
        bytes,
        serialize::Serialize,
        varint::VarInt
    },
    hash,
    tx::Witness
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
    script_sigs: Vec<Option<Script>>, //scriptSigs are stored in this attribute
    sighashes: Vec<Option<SigHash>>   //SigHash is stored to detect if new inputs/outputs can be added
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
    CannotGetInputValue()
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
    pub fn sign_input(&mut self, index: usize, key: &PrivKey, sighash: SigHash) -> Result<(), BuilderErr> {
        //Return an error if the given input index is larger than the total amount of inputs
        if self.inputs.len() < index {
            return Err(BuilderErr::InvalidInputIndex(index))
        }
        
        //Create a copy of the transaction
        let tx_copy: Tx = Tx::construct(self.inputs.clone(), self.outputs.clone(), 0, false);

        //Get the unlocking script type of the input
        let script_pub_key: Script = Script::new(Self::get_input_script_pub_key(&self, index)?);
        let input_script_type: ScriptType = match Script::determine_type(&script_pub_key) {
            Ok(x) => match x {
                ScriptType::P2WPKH | ScriptType::P2WSH => {
                    self.inputs[index].segwit = true;
                    x
                },
                _ => x
            },
            Err(_) => return Err(BuilderErr::UnknownScriptType())
        };
        
        //Sign the input and set the script_sig based on the locking script
        match input_script_type {
            ScriptType::P2PKH => self.p2pkh_pipe(&tx_copy, index, &sighash, &script_pub_key, &key)?,
            ScriptType::P2SH => Self::p2sh_pipe()?,           //Implement a custom P2SH signing function here
            ScriptType::P2WPKH => self.p2wpkh_pipe(&tx_copy, index, &sighash, &script_pub_key, &key)?,
            ScriptType::P2WSH => Self::p2wsh_pipe()?          //P2SH signing but with BIP-143
        }

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
        Determine what script type the inputted script is.
        Returns error if cannot tell.
    */
    pub fn determine_script_type(&mut self, script: &Vec<u8>, index: usize) -> Result<ScriptType, BuilderErr> {
        let input_script_type: ScriptType = match script[0] {
            0x76 => ScriptType::P2PKH,
            0xA9 => ScriptType::P2SH,
            0x00 => {
                match Self::get_input_script_pub_key(&self, index)?[1] {
                    0x14 => {
                        self.inputs[index].segwit = true;
                        ScriptType::P2WPKH
                    },
                    0x20 => { 
                        self.inputs[index].segwit = true;
                        ScriptType::P2WSH
                    } ,
                    _ => return Err(BuilderErr::UnknownScriptType())
                } 
            },
            _ => return Err(BuilderErr::UnknownScriptType())
        };

        Ok(input_script_type)
    }

    /**
        Modifies the tx to be signed based on the sighash. 
        Uses the non Segwit serialization
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
        Modifies the transaction based on the Sighash to be signed.
        See BIP-143 for specification.
    */
    fn segwit_tx_modification(
        &self,
        tx_copy: &Tx,
        sighash: &SigHash,
        index: usize,
        script_code: &Script
    ) -> Result<Vec<u8>, BuilderErr> {
        let n_version = tx_copy.version.to_le_bytes();
        
        //hashPrevouts is the SHA256D of all input outpoints if ANYONECANPAY is not set
        //If ANYONECANPAY is set, hashPrevOuts is [0; 32]
        let hash_prevouts: [u8; 32] = match sighash {
            SigHash::ALL | SigHash::NONE | SigHash::SINGLE
            => {
                let mut outpoints = vec![];
                for i in 0..tx_copy.inputs.len() {
                    outpoints.append(&mut bytes::reverse(&tx_copy.inputs[i].txid.to_vec()));
                    outpoints.append(&mut tx_copy.inputs[i].vout.to_le_bytes().to_vec());
                }
                hash::sha256d(outpoints)
            },
            
            _ => [0; 32]
        };

        //hashSequence is the SHA256D of of the sequence of all inputs if ANYONECANPAY, NONE or SINGLE are not set.
        //else it is [0; 32]
        let hash_sequence: [u8; 32] = match sighash {
            SigHash::ALL => {
                let mut sequences = vec![];
                for i in 0..tx_copy.inputs.len() {
                    sequences.append(&mut tx_copy.inputs[i].sequence.to_le_bytes().to_vec());
                }
                hash::sha256d(sequences)
            },
            
            _ => [0; 32]
        };

        //hashOutputs is the SHA256D of all outputs if SigHash is not single, [0; 32] is SigHash is none
        //and the output at the same index as the input being signed if the SigHash is single.
        let hash_outputs: [u8; 32] = match sighash {
            SigHash::SINGLE => {
                if index >= tx_copy.outputs.len() { return Err(BuilderErr::OutputIndexMissing(index)) }
                let mut output = vec![];
                output.append(&mut tx_copy.outputs[index].serialize().unwrap());
                hash::sha256d(output)
            },
            SigHash::NONE => [0; 32],
            _ => {
                let mut outputs = vec![];
                for i in 0..tx_copy.outputs.len() {
                    outputs.append(&mut tx_copy.outputs[index].serialize().unwrap());
                }
                hash::sha256d(outputs)
            },
        };

        let input_value: u64 = match api::JsonRPC::new(&self.network).get_input_value(&bytes::encode_02x(&tx_copy.inputs[index].txid), tx_copy.inputs[index].vout){
            Ok(x) => x,
            Err(_) => return Err(BuilderErr::CannotGetInputValue())
        };

        let mut script_code = script_code.code.clone();
        script_code.remove(0);
        script_code.remove(0);
        script_code.splice(0..0, vec![0x19, 0x76, 0xa9, 0x14]);
        script_code.append(&mut vec![0x88, 0xac]);

        let mut outpoint: Vec<u8> = vec![];
        outpoint.append(&mut bytes::reverse(&tx_copy.inputs[index].txid.to_vec()));
        outpoint.append(&mut tx_copy.inputs[index].vout.to_le_bytes().to_vec());


        let mut bip143_prehash_serialization: Vec<u8> = vec![];
        bip143_prehash_serialization.append(&mut n_version.to_vec());                                        //version
        bip143_prehash_serialization.append(&mut hash_prevouts.to_vec());                                    //hashPrevout
        bip143_prehash_serialization.append(&mut hash_sequence.to_vec());                                    //hashSequence
        bip143_prehash_serialization.append(&mut outpoint);
        bip143_prehash_serialization.append(&mut script_code);                                               //scriptCode of the input
        bip143_prehash_serialization.append(&mut input_value.to_le_bytes().to_vec());                        //Input value
        bip143_prehash_serialization.append(&mut tx_copy.inputs[index].sequence.to_le_bytes().to_vec());     //Input sequence
        bip143_prehash_serialization.append(&mut hash_outputs.to_vec());                                     //hashOutputs
        bip143_prehash_serialization.append(&mut tx_copy.locktime.to_le_bytes().to_vec());                   //Locktime of the transaction
        let sh: u32 = match sighash {
            SigHash::ALL => 0x01,
            SigHash::NONE => 0x02,
            SigHash::SINGLE => 0x03,
            SigHash::ALL_ANYONECANPAY => 0x81,
            SigHash::NONE_ANYONECANPAY => 0x82,
            SigHash::SINGLE_ANYONECANPAY => 0x83
        };
        bip143_prehash_serialization.append(&mut sh.to_le_bytes().to_vec());                                 //Sighash
    
        

        Ok(bip143_prehash_serialization)
    }

    /**
        Sign the modified tx using the provided secret key and sighash
    */  
    fn sign_p2pkh_input(tx_copy: &Tx, sighash: &SigHash, key: &PrivKey) -> Result<Signature, BuilderErr> {
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

        //Sign the input
        Ok(signature::sign(&msg, &key.raw()))
    }

    /**
        Input signing pipe for P2PKH inputs
    */
    fn p2pkh_pipe(
        &mut self, 
        tx_copy: &Tx,
        index: usize,
        sighash: &SigHash,
        script_pub_key: &Script,
        key: &PrivKey
    ) -> Result<(), BuilderErr> {
        let mut tx_copy = tx_copy.clone();
        
        //Add the script pub key of the input currently being signed as the scriptSig
        tx_copy.inputs[index].scriptSig = script_pub_key.clone();
        tx_copy.inputs[index].scriptSig_size = tx_copy.inputs[index].scriptSig.len() as u64;
        

        //Based on the provided SigHash, modify the transaction data
        Self::modify_tx_copy(&mut tx_copy, &sighash, index)?;

        //Sign the modified tx_copy
        //Currently, only P2PKH signing is implemented
        let signature: Signature = Self::sign_p2pkh_input(&tx_copy, &sighash, &key)?;
 
        
        //Construct the scriptSig for the input
        let script_sig: Script = Script::pkh_unlocking(&signature, &key, sighash);

        //Store the scriptSig and sighash to use later  
        self.script_sigs[index] = Some(script_sig);
        self.sighashes[index] = Some(sighash.clone());


        
        Ok(())
    }

    /**
        Input signing pipe for P2WPKH inputs
    */
    fn p2wpkh_pipe(
        &mut self, 
        tx_copy: &Tx,
        index: usize,
        sighash: &SigHash,
        script_pub_key: &Script,
        key: &PrivKey
    ) -> Result<(), BuilderErr> {
        let bip143_serialized_tx: Vec<u8> = self.segwit_tx_modification(tx_copy, sighash, index, script_pub_key)?;
        println!("{}", bip143_serialized_tx.len());
        let hash: [u8; 32] = hash::sha256d(bip143_serialized_tx);

        let msg = match signature::new_msg(&hash) {
            Ok(x) => x,
            Err(_) => return Err(BuilderErr::FailedToCreateMessageStruct())
        };

        let signature = signature::sign(&msg, &key.raw());

        //Construct the scriptSig for the input
        let script_sig: Script = Script::pkh_unlocking(&signature, &key, sighash);

        //Store the scriptSig and sighash to use later  
        self.script_sigs[index] = Some(script_sig);
        self.sighashes[index] = Some(sighash.clone());

        
        Ok(())
    }

    /**
        Input signing pipe for P2SH inputs
    */
    fn p2sh_pipe() -> Result<(), BuilderErr> {
        todo!();
    }

    /**
        Input signing pipe for P2WSH inputs
    */
    fn p2wsh_pipe() -> Result<(), BuilderErr> {
        todo!();
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
                    input.scriptSig_size = input.scriptSig.len();

                    inputs.push(input);
                },
                
                //If input is not signed, return an error
                None => return Err(BuilderErr::UnsignedInput(i))
            }
        }

        //If any of the inputs in the Tx are marked as SegWit, set the SegWit data
        let mut segwit: bool = false;
        let mut flag: Option<u8> = None;
        let mut marker: Option<u8> = None;
        let mut witness: Option<Vec<Witness>> = None;
        if self.inputs.iter().any(|x| x.segwit == true) {
            segwit = true;
            //If the Tx is SegWit,values here are set
            flag = Some(0x00);
            marker = Some(0x01);
            witness = Some(vec![Witness::empty(); self.inputs.len()]);

            //For each input, if the input is SegWit, remove it's scriptSig and store it in the Witness array
            for i in 0..self.inputs.len() {
                if self.inputs[i].segwit {
                    inputs[i].scriptSig_size = 0x00;
                    inputs[i].scriptSig = Script::new(vec![]);
                    
                    let mut wd: Vec<Witness> = match witness {
                        Some(x) => x,
                        None => panic!("WTF")
                    };
                    wd[i] = Witness::new(self.script_sigs[i].clone().unwrap(), 2);
                    
                    witness = Some(wd);
                } else {
                    
                    let mut wd: Vec<Witness> = match witness {
                        Some(x) => x,
                        None => panic!("WTF")
                    };
                    wd[i] = Witness::empty();
                    witness = Some(wd);
                }
            }
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