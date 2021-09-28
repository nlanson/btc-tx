use crate::{
    Digest, Sha256,
    util::bytes
};

/**
    Takes in a byte array and returns the sha256 hash of it as a byte array of length 32
*/
pub fn sha256<T>(input: T) -> [u8; 32]
where T: AsRef<[u8]>
{
    let mut r = Sha256::new();
    r.update(input);
    bytes::try_into(r.finalize().to_vec())
                    
}

/**
Double SHA256 encrypt the input data
*/
pub fn sha256d<T>(input: T) -> [u8; 32]
where T: AsRef<[u8]>
{
    let round1 = sha256(input);
    sha256(round1)
}