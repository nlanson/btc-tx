use btc_keyaddress::prelude::try_into;

/**
    Method to reverse the byte order of a byte vec
*/
pub fn reverse_bytes(bytes: &Vec<u8>) -> Vec<u8> {
    bytes.iter().rev().map(|x| *x).collect()
}

/*
    Decodes hex strings into a byte vector
*/
pub fn decode_02x(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("Hex decode error"))
        .collect::<Vec<u8>>()
}

/*
    Encodes byte slices into hex string
*/
pub fn encode_02x(bytes: &[u8]) -> String {
    bytes.iter().map(|x| {
        format!("{:02x}", x)
    }).collect::<String>()
}


pub struct VarInt();
impl VarInt {
    pub fn from_usize(n: usize) -> Result<Vec<u8>, ()> {
        let mut n_bytes = n.to_le_bytes().to_vec();

        let prefix: Option<u8> = match n {
            0..=0xfc => {
                None
            },
            0xfd..=0xffff => {
                Some(0xfd)
            },
            0x10000..=0xffffffff => {
                Some(0xfe)
            },
            0x100000000..=0xffffffffffffffff => {
                Some(0xff)
            },
            _ => return Err(())
        };
    
        match prefix {
            Some(x) => {
                match x {
                    0xfd => n_bytes.truncate(2),
                    0xfe => n_bytes.truncate(4),
                    _ => n_bytes.truncate(8)
                }
                
                n_bytes.splice(0..0,vec![x]);
            },
            None => n_bytes.truncate(1)
        }

        Ok(n_bytes)
    }
}

pub fn varint(count: usize) -> Result<Vec<u8>, ()> {
    let prefix: Result<Option<u8>, ()> = match count {
        0..=0xfc => {
            Ok(None)
        },
        0xfd..=0xffff => {
            Ok(Some(0xfd))
        },
        0x10000..=0xffffffff => {
            Ok(Some(0xfe))
        },
        0x100000000..=0xffffffffffffffff => {
            Ok(Some(0xff))
        },
        _ => Err(())
    };

    let mut varint: Vec<u8> = vec![];
    match prefix {
        Ok(x) => {
            match x {
                Some(n) => {
                    varint.push(n);
                },
                None => { }
            }
            let val = reverse_bytes(
                &count.to_be_bytes()
                .to_vec()
            );
            val.iter().for_each(|n| varint.push(*n) );
        },
        Err(_) => {
            return Err(())
        }
    }

    return Ok(varint)
}