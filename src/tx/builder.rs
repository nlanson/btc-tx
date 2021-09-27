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
    signature,
    util::{
        Network
    }
};

#[allow(non_camel_case_types)]
pub enum SigHash {
    ALL,
    NONE,
    SINGLE,
    ALL_ANYONECANPAY,
    NONE_ANYONECANPAY,
    SINGLE_ANYONECANPAY
}

pub struct TxBuilder {
    inputs: Vec<Input>,
    outputs: Vec<Output>
}

pub enum BuilderErr {

}

impl TxBuilder {
    pub fn new(network: Network) -> Self {
        Self {
            inputs: vec![],
            outputs: vec![]
        }
    }

    pub fn add_input(&mut self, txid: [u8; 32], vout: u32) {
        let new_in: Input = Input::unsigned_input(txid, vout, 0xFFFFFFFF);
        self.inputs.push(new_in);
    }

    pub fn add_output(&mut self, address: &str, value: u64) {
        let new_out: Output = Output::new(address, value);
        self.outputs.push(new_out);
    }
}