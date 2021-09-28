use btc_tx::*;
use btc_tx::{
    util::serialize::Serialize
};
use btc_keyaddress::key::Key;
use btc_keyaddress::prelude::encode_02x;
use btc_keyaddress::key::PrivKey as PrivKey;
use btc_keyaddress::key::PubKey as PubKey;

fn main() {
    //create_and_verify_data();
    create_testnet_tx();
}

fn create_testnet_tx() {
    let mut txb = tx::TxBuilder::new(util::Network::Test);
    txb.add_input("a8064a6143c6027dddafb356236a475dab3f56fa3dad1dc0c873e54e6527f167", 1);
    txb.add_output("msSJzRfQb2T3hvws3vRhqtK2Ao39cabEa2", 80000);


    let key: PrivKey = PrivKey::from_slice(&[25, 185, 89, 6, 72, 28, 43, 234, 167, 160, 163, 78, 240, 86, 146, 133, 49, 98, 255, 253, 45, 121, 146, 10, 233, 252, 142, 232, 193, 73, 255, 150]).unwrap();
    txb.sign_input(0, key, tx::SigHash::ALL).unwrap();
    let tx: tx::Tx = txb.build().unwrap();
    println!("{}", encode_02x(&tx.serialize().unwrap()));
}

fn create_and_verify_data() {
    //Create a new random private key and a message filled with zeroes.
    let sk = PrivKey::new_rand();
    let my_msg = [255; 32];

    //Convert the message into the message struct
    let msg = signature::new_msg(&my_msg).unwrap();
    
    //Sign the message with the private key
    let sig = signature::sign(&msg, &sk.raw()); 
    
    //Verify the signature
    match signature::verify(&sig, &msg, &PubKey::from_priv_key(&sk).raw()) {
        Ok(x) => println!("Message verified!"),
        Err(x) => println!("{:?}", x)
    }

    //Serialize and deserialize the signature
    let ss: SerializedSignature = util::serialize::serialize_sig(&sig);
    let dess: Signature = util::serialize::deserialize_sig(&ss).unwrap();
    
    println!("{:02x?}", ss.to_vec());

    //Verify the deserialized signature
    match signature::verify(&dess, &msg, &PubKey::from_priv_key(&sk).raw()) {
        Ok(x) => println!("Message verified!"),
        Err(x) => println!("{:?}", x)
    }
}
