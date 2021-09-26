use crate::{
    util
};

use super::{
    input::Input,
    output::Output
};


pub struct Tx {
    pub version: u32,          //4byte (32bit) integer                           (little endian)
    pub input_count: u64,      //To be converted into a VarInt for serialization
    pub inputs: Vec<Input>,    //List of UTXOs to consume
    pub output_count: u64,     //To be converted into a VarInt for serialization
    pub outputs: Vec<Output>,  //List of UTXOs to create
    pub locktime: u32          //4byte (32bit) integer                           (little endian)
}

impl Tx {
    pub fn create(version: u32,  inputs: Vec<Input>, outputs: Vec<Output>, locktime: u32) -> Self {
        Self {
            version,
            input_count: inputs.len() as u64,
            inputs,
            output_count: outputs.len() as u64,
            outputs,
            locktime
        }
    }
}