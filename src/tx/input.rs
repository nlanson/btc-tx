/*
    Input struct representing UTXOs to be consumed in
    a transaction.
*/

#[derive(Clone)]
pub struct Input {
    txid: [u8; 32],           //Pointer to the tx containing UTXO to be spent    (little endian)
    output_index: [u8; 4],    //The index number of the UTXO in the referred tx  (little endian)
    script_sig_size: Vec<u8>, //VarInt
    script_sig: Vec<u8>,      //Unlocking script
    sequence: [u8; 4]         //Used for locktime or disabled (0xFFFFFFFF)       (little endian)
}