use crate::{
    util::{
        serialize::{
            Serialize,
            serialize_sig,
            SerializationError
        },
        varint::VarInt
    },
    tx::{
        Script,
        SigHash
    },
    Signature,
    Key, PrivKey, PubKey
};

#[derive(Debug, Clone)]
pub struct Witness {
    stack: Vec<Script>
}


impl Witness {
    pub fn new(stack_items: Vec<Script>) -> Self {
        Self {
            stack: stack_items
        }
    }

    pub fn empty() -> Self {
        Self {
            stack: vec![]
        }
    }

    pub fn len(&self) -> usize {
        self.stack.len()
    }

    /**
        Create witness for P2WPKH
    */
    pub fn p2wpkh(signature: &Signature, signing_key: &PrivKey, sighash: &SigHash) -> Self {
        //Serialize the signature and append the sighash byte
        let mut serialized_signature = serialize_sig(signature).to_vec();
        serialized_signature.push(sighash.clone() as u8);

        let pubkey = PubKey::from_priv_key(signing_key).as_bytes::<33>().to_vec();

        let stack_items: Vec<Script> = vec![
            Script::new(serialized_signature),
            Script::new(pubkey)
        ];

        Self {
            stack: stack_items
        }
    }
}

impl Serialize for Witness {
    fn serialize(&self) -> Result<Vec<u8>, SerializationError> {
        //If the witness is empty, return 0x00
        if self.len() == 0 { return Ok(vec![0x00]) }

        let mut witness_bytes: Vec<u8> = vec![];
        let mut stack_size_varint = match VarInt::from_usize( self.len() ) {
            Ok(x) => x,
            Err(_) => return Err(SerializationError::VarIntErr( self.len() ))
        };
        witness_bytes.append(&mut stack_size_varint);
        for i in 0..self.len() {
            //Length of the stack item
            witness_bytes.append(
                &mut VarInt::from_usize(self.stack[i].code.len()).unwrap()
            );
            
            //The stack item itself
            witness_bytes.append(
                &mut self.stack[i].code.clone()
            );
        }

        Ok(witness_bytes)
    }
}