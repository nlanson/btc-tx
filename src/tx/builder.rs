/*
    Module that creates and signs transactions

    Todo:
        - Implement signing of individual inputs. This involves creating the dummy transaction data to use as the signing message.
        - Track how many inputs have been signed and what sighash was used.
        - Depending on sighashes used, allow or deny new inputs/ouputs to be added
*/
use super::{
    Input, Output, Tx,
};

use crate::{
    Signature,
    signature,
    util::{
        Network,
        bytes
    },
    SecretKey,
    api
};

#[allow(non_camel_case_types)]
#[derive(Debug)]
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
    signatures: Vec<(Option<Signature>, Option<SigHash>)>
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
            signatures: vec![]
        }
    }

    pub fn add_input(&mut self, txid: &str, vout: u32) {
        let txid_bytes: [u8; 32] = bytes::try_into(bytes::decode_02x(txid));
        let new_in: Input = Input::unsigned_input(txid_bytes, vout, 0xFFFFFFFF);
        self.inputs.push(new_in);
        self.signatures.push((None, None));
    }

    pub fn add_output(&mut self, address: &str, value: u64) {
        let new_out: Output = Output::new(address, value);
        self.outputs.push(new_out);
    }

    pub fn sign_input(&mut self, index: usize, key: SecretKey, sighash: SigHash) -> Result<(), BuilderErr> {
        // Sign the input at the given index with the given key and given sighash.
        //  - Depending on the selected sigHash, modify the transaction as needed to construct the bytes to sign.
        //  - Sign the TxData and use the signature and pub key to construct the correct scriptSig OP_CODES based on the 
        //     locking script attached to the input

        let mut txCopy: Tx = Tx::construct(self.inputs.clone(), self.outputs.clone(), 0);
        txCopy.inputs[index].scriptSig = vec![0x00];       //This should be the locking script of self
        txCopy.inputs[index].scriptSig_size = txCopy.inputs[index].scriptSig.len() as u64;

        //Serialize the txCopy after modifications
        //Append the sig hash type
        //Sign with secret key
        //Construct and store scriptSig based on the scriptPubKey


        todo!();
    }
}