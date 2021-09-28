pub use btc_keyaddress::prelude::*;

pub mod bytes;
pub mod serialize;
pub mod varint;
pub mod script;

#[derive(Debug)]
pub enum Network {
    Main,
    Test
}

pub use script::Script as Script;