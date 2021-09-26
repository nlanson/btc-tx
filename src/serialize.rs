/*
    Serialization module that implements the serialization of 
    various parts of a transaction.
*/
use crate::{
    Signature, SerializedSignature
};

#[derive(Debug)]
pub enum SerializationError {
    CantDeserialize()
}

/**
    Serialize a signature.
    The serialization does not contain the sighash flag.
*/
pub fn serialize_sig(sig: &Signature) -> SerializedSignature {
    SerializedSignature::from_signature(sig)
}

/**
    Deserialize a serialized signature.
    The serialized signature input should not contain the sig hash
*/
pub fn deserialize_sig(sig: &SerializedSignature) -> Result<Signature, SerializationError> {
    match SerializedSignature::to_signature(sig) {
        Ok(x) => Ok(x),
        Err(_) => Err(SerializationError::CantDeserialize())
    }
}