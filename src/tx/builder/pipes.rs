use crate::{
    tx::TxBuilder,
    tx::Tx,
    tx::SigHash,
    tx::Script,
    PrivKey,
    signature,
    hash
};
use super::{ 
    hashpreimage,
    BuilderErr
};

/**
    Signing pipe for P2PKH inputs
*/
pub fn p2pkh(
    builder: &mut TxBuilder,
    tx_copy: &Tx,
    index: usize,
    sighash: &SigHash,
    script_pub_key: &Script,
    key: &PrivKey
) -> Result<(), BuilderErr> {
    let mut tx_copy = tx_copy.clone();

    //Modify and get the hash preimage of the transaction
    let hash_preimage = hashpreimage::legacy(&mut tx_copy, sighash, index, script_pub_key)?;

    //Hash the preimage and sign it with the key.
    let msg = match signature::new_msg(&hash::sha256d(&hash_preimage)) {
        Ok(x) => x,
        Err(_) => return Err(BuilderErr::FailedToCreateMessageStruct())
    };
    let signature = signature::sign(&msg, &key.raw());

    //Construct and store the scriptSig and sigHash
    let script_sig: Script = Script::pkh_unlocking(&signature, &key, sighash);
    builder.script_sigs[index] = Some(script_sig);
    builder.sighashes[index] = Some(sighash.clone());
    
    
    Ok(())
}

/**
    Signing pipe for P2WPKH inputs
*/
pub fn p2wpkh(
    builder: &mut TxBuilder, 
    tx_copy: &Tx,
    index: usize,
    sighash: &SigHash,
    script_pub_key: &Script,
    key: &PrivKey
) -> Result<(), BuilderErr> {
    //Get the BIP143 defined hash preimage of the transaction and hash it
    let hash_preimage = hashpreimage::segwit(&builder.network, tx_copy, sighash, index, script_pub_key)?;
    let hash: [u8; 32] = hash::sha256d(hash_preimage);

    //Sign the hash preimage with the provided key
    let msg = match signature::new_msg(&hash) {
        Ok(x) => x,
        Err(_) => return Err(BuilderErr::FailedToCreateMessageStruct())
    };
    let signature = signature::sign(&msg, &key.raw());

    //Construct the scriptSig and store it and the sighash for later use
    let script_sig: Script = Script::pkh_unlocking(&signature, &key, sighash); 
    builder.script_sigs[index] = Some(script_sig);
    builder.sighashes[index] = Some(sighash.clone());

    
    Ok(())
}

pub fn p2sh() -> Result<(), BuilderErr> {
    unimplemented!();
    //P2SH will be similar to P2PKH but there may be multiple signatures in the scriptSig.
    //The script sig will consist of the redeem script provided by the user and the signature of
    //however many private keys the user provides
}

pub fn p2wsh() -> Result<(), BuilderErr> {
    unimplemented!();
    //P2WSH need to read and follow BIP143 spec
}