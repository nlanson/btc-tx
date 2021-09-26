#[allow(non_snake_case)]
/*
    Input struct representing UTXOs to be consumed in
    a transaction.
*/

#[derive(Clone)]
pub struct Input {
    txid: [u8; 32],         //Pointer to the tx containing UTXO to be spent    (little endian)
    vout: u32,              //The index number of the UTXO in the referred tx  (little endian)
    scriptSig_size: u64,    //To be converted into a VarInt for serialization
    scriptSig: Vec<u8>,     //Unlocking script opcodes   
    sequence: u32           //4byte (32bit) integer                            (little endian)
}