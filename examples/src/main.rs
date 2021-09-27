use btc_tx::*;
use btc_keyaddress::key::PrivKey as PrivKey;
use btc_keyaddress::key::PubKey as PubKey;

fn main() {
    create_and_verify_data();
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
