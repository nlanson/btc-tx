/*
    Module that makes writing script easier.
*/

#[allow(non_camel_case_types)]
pub enum Script {
    //Null Data / False
    OP_0 = 0x00,
    
    //P2PKH Codes
    OP_DUP = 0x76,
    OP_HASH160 = 0xA9,
    OP_EQUALVERIFY = 0x88,
    OP_CHECKSIG = 0xAC,

    //P2SH Codes
    OP_EQUAL = 0x87
}