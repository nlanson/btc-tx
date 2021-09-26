use crate::{
    util
};

use super::{
    input::Input,
    output::Output
};


#[derive(Debug, Clone)]
pub struct Tx {
    pub version: u32,          //4byte (32bit) integer                           (little endian)
    pub input_count: u64,      //To be converted into a VarInt for serialization
    pub inputs: Vec<Input>,    //List of UTXOs to consume
    pub output_count: u64,     //To be converted into a VarInt for serialization
    pub outputs: Vec<Output>,  //List of UTXOs to create
    pub locktime: u32          //4byte (32bit) integer                           (little endian)
}

impl Tx {
    /**
        Constructs a basic P2PKH transaction that is fully signed.
    */
    pub fn construct_p2pkh_tx(
        inputs: Vec<Input>,   //The inputs here are unsigned inputs.
        outputs: Vec<Output>,
        locktime: u32 
    ) -> Self {
        let mut tx: Tx = Self {
            version: 01,
            input_count: inputs.len() as u64,
            inputs,
            output_count: outputs.len() as u64,
            outputs,
            locktime
        };

        let txCopy: Tx = tx.clone();
        let mut signed_inputs: Vec<Input> = vec![];
        for i in 0..tx.inputs.len() {
            signed_inputs.push(Input::sign_input(&txCopy, i as u64));
        }
        tx.inputs = signed_inputs;

        tx
    }
}