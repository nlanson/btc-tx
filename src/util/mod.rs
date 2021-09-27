pub use btc_keyaddress::prelude::*;

pub mod bytes;
pub mod serialize;
pub mod varint;
pub mod script;

pub enum Network {
    Main,
    Test
}