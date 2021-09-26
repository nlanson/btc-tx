use crate::{
    Signature, Message, Secp256k1,
    SecretKey, PublicKey
};

#[derive(Debug)]
pub enum SigError {
    SigningErr(),
    BadMsgData(),
    CantVerify()
}

/**
    Create a signature from a message and private key
*/
pub fn sign(msg: &Message, sk: &SecretKey) -> Signature {
    Secp256k1::signing_only().sign_low_r(msg, sk)
}

/**
    Create a new message struct from a byte array
*/
pub fn new_msg(data: &[u8]) -> Result<Message, SigError> {
    match Message::from_slice(data) {
        Ok(x) => Ok(x),
        Err(_) => Err(SigError::BadMsgData())
    }
}

/**
    Verify a message using the signature and public key
*/
pub fn verify(sig: &Signature, msg: &Message, pk: &PublicKey) -> Result<(), SigError> {
    match Secp256k1::verification_only().verify(msg, sig, pk) {
        Ok(_) => Ok(()),
        Err(_) => Err(SigError::CantVerify())
    }
}