/*
    Serialization module that implements the serialization of 
    various parts of a transaction.
*/

/**
    Blanket trait to implement into structs that need to be serialized.
    Implementations may vary based on what needs to be byte reversed and etc...
*/
pub trait Serialize {
    fn serialize(&self) -> Vec<u8>;
}