/*
    Output struct representing UTXOs to be created by
    a transaction
*/

#[derive(Clone)]
pub struct Output {
    pub value: Vec<u8>,               //8 bytes representing value in satoshi  (little endian)
    pub script_pub_key_size: Vec<u8>, //VarInt
    pub script_pub_key: Vec<u8>       //Locking script
}