/*
    Output struct representing UTXOs to be created by
    a transaction
*/

#[derive(Debug, Clone)]
pub struct Output {
    pub value: u64,                   //Amount locked in output in Satoshis   (little endian)
    pub script_pub_key_size: u64,     //To be converted into a VarInt for serialization
    pub script_pub_key: Vec<u8>       //Locking script opcodes
}