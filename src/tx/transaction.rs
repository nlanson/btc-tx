use crate::{
    util
};

use super::{
    input::Input,
    output::Output
};


pub struct Tx {
    pub version: [u8; 4],      //4 bytes (little endian)
    pub input_count: Vec<u8>,  //VarInt
    pub inputs: Vec<Input>,    //List of UTXOs to consume
    pub output_count: Vec<u8>, //VarInt
    pub outputs: Vec<Output>,  //List of UTXOs to create
    pub locktime: [u8; 4]      //4 bytes (little endian)
}

impl Tx {
    pub fn create(version: [u8; 4],  inputs: Vec<Input>, outputs: Vec<Output>, locktime: [u8; 4]) -> Self {
        Self {
            version,
            input_count: util::VarInt::from_usize(inputs.len()).unwrap(),
            inputs,
            output_count: util::varint(outputs.len()).unwrap(),
            outputs,
            locktime
        }
    }
}