/*
    The examples with broadcasted TXs can be used in unit tests
*/

use btc_tx::*;
use btc_tx::{
    util::serialize::Serialize
};
use btc_keyaddress::key::Key;
use btc_keyaddress::prelude::*;
use btc_keyaddress::key::PrivKey as PrivKey;
use btc_keyaddress::key::PubKey as PubKey;

fn main() {
    //segwit_tx2();
    //segwit_tx();
    multi_in_segwit_tx1();
}

/**
    TX BROADCASTED
    TXID: d37c3d75e7a70261bf191dfc296272cbb20e0466167d4f6f8fde6c2458f05004
*/
fn legacy_tx() {
    let mut txb = tx::TxBuilder::new(util::Network::Test);
    txb.add_input("a8064a6143c6027dddafb356236a475dab3f56fa3dad1dc0c873e54e6527f167", 1);
    txb.add_output("msSJzRfQb2T3hvws3vRhqtK2Ao39cabEa2", 80000);


    let key: PrivKey = PrivKey::from_slice(&[25, 185, 89, 6, 72, 28, 43, 234, 167, 160, 163, 78, 240, 86, 146, 133, 49, 98, 255, 253, 45, 121, 146, 10, 233, 252, 142, 232, 193, 73, 255, 150]).unwrap();
    let signing_data = tx::SigningData::new(vec![key], None);
    txb.sign_input(0, &signing_data, tx::SigHash::ALL).unwrap();
    let tx: tx::Tx = txb.build().unwrap();
    println!("{}", encode_02x(&tx.serialize().unwrap()));
}

/**
    TX BROADCASTED
    TXID: 10296b2590ce4397a617cf77071581fc0eb34dc531b1c243565d7508970e57b7
*/
fn segwit_tx() {
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

/**
    Segeit tx with 2 outputs
    BROADCASTED d8f1b1529a1f2db2ae09da0e8e5bc562dbdddc7647f8154d1f7d1360e2cde1c6
*/
fn segwit_tx2() {
    let mut txb = tx::TxBuilder::new(util::Network::Test);
    txb.add_input("10296b2590ce4397a617cf77071581fc0eb34dc531b1c243565d7508970e57b7", 0);
    txb.add_output("tb1qj8rvxxnzkdapv3rueazzyn434duv5q5ep3ze5e", 29000);
    txb.add_output("tb1qj8rvxxnzkdapv3rueazzyn434duv5q5ep3ze5e", 29000);
    
    let key: PrivKey = PrivKey::from_slice(&[131, 187, 80, 16, 233, 20, 231, 76, 171, 218, 189, 168, 220, 150, 47, 40, 73, 149, 85, 236, 159, 205, 198, 160, 182, 32, 149, 30, 95, 184, 54, 186]).unwrap();
    let signing_data = tx::SigningData::new(vec![key], None);
    txb.sign_input(0, &signing_data, tx::SigHash::ALL);
    let tx: tx::Tx = txb.build().unwrap();
    println!("{}", encode_02x(&tx.serialize().unwrap()));
}

/**
    Segwit TX with multiple inputs and signed with SINGLE and ALL
    BROADCASTED 552af0fc08762799412d40c339c9c094981e353b161983c3e46b55b2a36dd8f0
*/
fn multi_in_segwit_tx1() {
    let mut txb = tx::TxBuilder::new(util::Network::Test);
    txb.add_input("d8f1b1529a1f2db2ae09da0e8e5bc562dbdddc7647f8154d1f7d1360e2cde1c6", 0);
    txb.add_input("d8f1b1529a1f2db2ae09da0e8e5bc562dbdddc7647f8154d1f7d1360e2cde1c6", 1);
    txb.add_output("tb1qj8rvxxnzkdapv3rueazzyn434duv5q5ep3ze5e", 50000);

    let key: PrivKey = PrivKey::from_slice(&[131, 187, 80, 16, 233, 20, 231, 76, 171, 218, 189, 168, 220, 150, 47, 40, 73, 149, 85, 236, 159, 205, 198, 160, 182, 32, 149, 30, 95, 184, 54, 186]).unwrap();
    let signing_data = tx::SigningData::new(vec![key], None);
    txb.sign_input(0, &signing_data, tx::SigHash::SINGLE_ANYONECANPAY);
    txb.sign_input(1, &signing_data, tx::SigHash::ALL);
    let tx: tx::Tx = txb.build().unwrap();
    println!("{}", encode_02x(&tx.serialize().unwrap()));

}
