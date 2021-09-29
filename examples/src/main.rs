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
    txb.sign_input(0, &key, tx::SigHash::ALL).unwrap();
    let tx: tx::Tx = txb.build().unwrap();
    println!("{}", encode_02x(&tx.serialize().unwrap()));
}

fn create_segwit_output_tx() {
    let mut txb = tx::TxBuilder::new(util::Network::Test);
    txb.add_input("d37c3d75e7a70261bf191dfc296272cbb20e0466167d4f6f8fde6c2458f05004", 0);
    txb.add_output("tb1qxauw2dslmtgdyzw73gtv9mzv5erp3xf7mt83vq", 70000);

    let key: PrivKey = PrivKey::from_slice(&[25, 185, 89, 6, 72, 28, 43, 234, 167, 160, 163, 78, 240, 86, 146, 133, 49, 98, 255, 253, 45, 121, 146, 10, 233, 252, 142, 232, 193, 73, 255, 150]).unwrap();
    txb.sign_input(0, &key, tx::SigHash::ALL).unwrap();
    let tx: tx::Tx = txb.build().unwrap();
    println!("{}", encode_02x(&tx.serialize().unwrap()));
}

fn create_segwit_tx() {
    let mut txb = tx::TxBuilder::new(util::Network::Test);
    txb.add_input("471157b07c3f6f5243c0b98a02614636cc6cde24371bcb69dc0bbd4efe52a742", 0);
    txb.add_output("tb1qxauw2dslmtgdyzw73gtv9mzv5erp3xf7mt83vq", 65000);
    
    let key: PrivKey = PrivKey::from_slice(&decode_02x("3a8c0c731cba400917f66bc3435a405387a9a5b20cdbfdedb19e37d0c6cad8b9")).unwrap();
    let address = btc_keyaddress::address::Address::testnet_p2wpkh(&PubKey::from_priv_key(&key)).unwrap();
    println!("{}", address);
    txb.sign_input(0, &key, tx::SigHash::ALL);
    let tx: tx::Tx = txb.build().unwrap();
    println!("{}", encode_02x(&tx.serialize().unwrap()));
}
