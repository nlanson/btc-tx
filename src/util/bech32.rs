/*
    Bech32 module
*/
use crate::{
    WitnessProgram
};

pub fn decode(address: &str) -> Vec<u8> {
    let decoded = WitnessProgram::from_address(&address).unwrap();
    decoded.to_scriptpubkey()
}