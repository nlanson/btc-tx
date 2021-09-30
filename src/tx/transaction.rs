use crate::{
    util::bytes::{
        decode_02x as d02,
        encode_02x as e02
    },
    util::serialize::{
        Serialize as SerializeTrait,
        SerializationError
    },
    util::varint::VarInt as VarInt,
};

use super::{
    input::Input,
    output::Output,
    Witness
};


#[derive(Debug, Clone)]
pub struct Tx {
    pub version: u32,                 //4byte (32bit) integer                           (little endian)
    pub marker: Option<u8>,           //Only present if tx is SegWit (0x00)
    pub flag: Option<u8>,             //Only present if tx is SegWit (0x01)
    pub input_count: u64,             //To be converted into a VarInt for serialization
    pub inputs: Vec<Input>,           //List of UTXOs to consume
    pub output_count: u64,            //To be converted into a VarInt for serialization
    pub outputs: Vec<Output>,         //List of UTXOs to create
    pub witness: Option<Vec<Witness>>,//Vector of witness bytes, only present if tx is SegWit
    pub locktime: u32,                //4byte (32bit) integer                           (little endian)
    pub segwit: bool                  //Internal marker
}

impl SerializeTrait for Tx {
    fn serialize(&self) -> Result<Vec<u8>, SerializationError> {
        let mut tx_bytes = vec![];
        let mut version_bytes = self.version.to_le_bytes().to_vec();
        let mut input_count = match VarInt::from_usize(self.inputs.len()) {
            Ok(x) => x,
            Err(_) => return Err(SerializationError::VarIntErr(self.inputs.len()))
        };
        let mut input_bytes = vec![];
        for i in 0..self.inputs.len() {
            let mut bytes = self.inputs[i].serialize()?;
            input_bytes.append(&mut bytes);
        }
        let mut output_count = match VarInt::from_usize(self.outputs.len()) {
            Ok(x) => x,
            Err(_) => return Err(SerializationError::VarIntErr(self.inputs.len()))
        };
        let mut output_bytes = vec![];
        for i in 0..self.outputs.len() {
            let mut bytes = self.outputs[i].serialize()?;
            output_bytes.append(&mut bytes);
        }
        let mut locktime_bytes = self.locktime.to_le_bytes().to_vec();
        

        //Concatenate the bytes
        //Add witness flags if the tx is marked as SegWit
        tx_bytes.append(&mut version_bytes);
        if self.segwit {
            tx_bytes.push(self.flag.unwrap());
            tx_bytes.push(self.marker.unwrap());
        }

        tx_bytes.append(&mut input_count);
        tx_bytes.append(&mut input_bytes);
        tx_bytes.append(&mut output_count);
        tx_bytes.append(&mut output_bytes);

        //Append the witness data if it exists
        if self.segwit {
            let witness_vec: Vec<Witness> = self.witness.clone().unwrap();

            let mut witness_bytes: Vec<u8> = vec![];
            for i in 0..witness_vec.len() {
                witness_bytes.append(&mut witness_vec[i].serialize()?)
            }

            //Append each Witness to the tx bytes
            tx_bytes.append(&mut witness_bytes);
        }
        tx_bytes.append(&mut locktime_bytes);

        Ok(tx_bytes)
    }
}

impl Tx {
    /**
        Constructs a basic non segwit transactions with given inputs and outputs.
        Used for signing transactions
    */
    pub fn construct(
        inputs: Vec<Input>,   //The inputs here are unsigned inputs.
        outputs: Vec<Output>,
        locktime: u32,
        segwit: bool 
    ) -> Self {
        if segwit {
            return Self {
                version: 01,
                marker: Some(0x00),
                flag: Some(0x01),
                input_count: inputs.len() as u64,
                inputs,
                output_count: outputs.len() as u64,
                outputs,
                witness: None,
                locktime,
                segwit: false
            }
        }
        
        Self {
            version: 01,
            marker: None,
            flag: None,
            input_count: inputs.len() as u64,
            inputs,
            output_count: outputs.len() as u64,
            outputs,
            witness: None,
            locktime,
            segwit: false
        }
    }
}