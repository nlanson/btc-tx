use btc_tx::*;
use btc_tx::{
    util::serialize::Serialize
};
use btc_keyaddress::key::Key;
use btc_keyaddress::prelude::*;
use btc_keyaddress::key::PrivKey as PrivKey;
use btc_keyaddress::key::PubKey as PubKey;

fn main() {
    //create_and_verify_data();
    //create_testnet_tx();
    //create_segwit_output_tx();
    create_segwit_tx();
}

fn create_testnet_tx() {
    let mut txb = tx::TxBuilder::new(util::Network::Test);
    txb.add_input("a8064a6143c6027dddafb356236a475dab3f56fa3dad1dc0c873e54e6527f167", 1);
    txb.add_output("msSJzRfQb2T3hvws3vRhqtK2Ao39cabEa2", 80000);


    let key: PrivKey = PrivKey::from_slice(&[25, 185, 89, 6, 72, 28, 43, 234, 167, 160, 163, 78, 240, 86, 146, 133, 49, 98, 255, 253, 45, 121, 146, 10, 233, 252, 142, 232, 193, 73, 255, 150]).unwrap();
    let signing_data = tx::SigningData::new(vec![key], None);
    txb.sign_input(0, &signing_data, tx::SigHash::ALL).unwrap();
    let tx: tx::Tx = txb.build().unwrap();
    println!("{}", encode_02x(&tx.serialize().unwrap()));
}

fn create_segwit_output_tx() {
    let mut txb = tx::TxBuilder::new(util::Network::Test);
    txb.add_input("04ff8603ec82938fe3effdde0df4033fb0cfd1c5b8285c5d0827df1a69508db1", 1);
    txb.add_output("tb1qj8rvxxnzkdapv3rueazzyn434duv5q5ep3ze5e", 70000);

    let key: PrivKey = PrivKey::from_slice(&[25, 185, 89, 6, 72, 28, 43, 234, 167, 160, 163, 78, 240, 86, 146, 133, 49, 98, 255, 253, 45, 121, 146, 10, 233, 252, 142, 232, 193, 73, 255, 150]).unwrap();
    let signing_data = tx::SigningData::new(vec![key], None);
    txb.sign_input(0, &signing_data, tx::SigHash::ALL).unwrap();
    let tx: tx::Tx = txb.build().unwrap();
    println!("{}", encode_02x(&tx.serialize().unwrap()));
}

fn create_segwit_tx() {
    let mut txb = tx::TxBuilder::new(util::Network::Test);
    txb.add_input("36e336b364abaf48b46c415903b1d93c7a740d7a3bde1691e30fec3d7a180245", 0);
    txb.add_output("tb1qj8rvxxnzkdapv3rueazzyn434duv5q5ep3ze5e", 60000);
    
    let key: PrivKey = PrivKey::from_slice(&[131, 187, 80, 16, 233, 20, 231, 76, 171, 218, 189, 168, 220, 150, 47, 40, 73, 149, 85, 236, 159, 205, 198, 160, 182, 32, 149, 30, 95, 184, 54, 186]).unwrap();
    let address = btc_keyaddress::address::Address::testnet_p2wpkh(&PubKey::from_priv_key(&key)).unwrap();
    let signing_data = tx::SigningData::new(vec![key], None);
    txb.sign_input(0, &signing_data, tx::SigHash::ALL);
    let tx: tx::Tx = txb.build().unwrap();
    println!("{}", encode_02x(&tx.serialize().unwrap()));
}
