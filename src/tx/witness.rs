use crate::{
    util::serialize::Serialize,
    util::serialize::SerializationError,
    util::varint::VarInt
};

#[derive(Debug, Clone)]
pub struct Witness {
    len: u64,
    data: Vec<u8>
}


impl Witness {
    pub fn new(data: Vec<u8>, stack_items: u64) -> Self {
        Self {
            len: stack_items,
            data,
        }
    }

    pub fn empty() -> Self {
        Self {
            len: 0x00,
            data: vec![0x00]
        }
    }
}

impl Serialize for Witness {
    fn serialize(&self) -> Result<Vec<u8>, SerializationError> {
        if self.len == 0 && self.data == vec![0x00] {
            return Ok(vec![0x00])
        }
        let mut witness_bytes: Vec<u8> = vec![];
        let mut stack_size_varint = match VarInt::from_usize(self.len as usize) {
            Ok(x) => x,
            Err(_) => return Err(SerializationError::VarIntErr(self.len as usize))
        };
        witness_bytes.append(&mut stack_size_varint);
        let mut wd: Vec<u8> = self.data.clone();
        witness_bytes.append(&mut wd);

        Ok(witness_bytes)
    }
}