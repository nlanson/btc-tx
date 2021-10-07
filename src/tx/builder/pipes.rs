use crate::{
    PrivKey,
    hash,
    signature, Signature,
    tx::{
        Script,
        SigningData,
        SigHash,
        Tx,
        TxBuilder,
        Witness,
        ScriptType
    }
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
    //The scriptCode under this circumstance is derived from the scriptPubKey from the input being signed
    let script_code = hashpreimage::script_code(script_pub_key);
    let hash_preimage = hashpreimage::segwit(&builder.network, tx_copy, sighash, index, &script_code)?;
    let hash: [u8; 32] = hash::sha256d(hash_preimage);

    //Sign the hash preimage with the provided key
    let msg = match signature::new_msg(&hash) {
        Ok(x) => x,
        Err(_) => return Err(BuilderErr::FailedToCreateMessageStruct())
    };
    let signature = signature::sign(&msg, &key.raw());

    //Create the witness and store it and the sighash
    let witness: Witness = Witness::p2wpkh(&signature, &key, sighash);
    builder.witness[index] = Some(witness);
    builder.sighashes[index] = Some(sighash.clone());

    
    Ok(())
}

/**
    Sign a legacy P2SH input.
    When constructing a scriptSig, it assumes the P2SH input is
    a multisig input (as these are the most common).
    
    However, if no keys are provided in the signing_data, it can handle 
    custom scripts.
*/
pub fn p2sh(
    builder: &mut TxBuilder,
    tx_copy: &Tx,
    index: usize,
    sighash: &SigHash,
    signing_data: &SigningData
) -> Result<(), BuilderErr> {
    match &signing_data.script {
        //If a redeem script is presented
        Some(x) =>  match x.determine_type() {
            /* Segwit within P2SH */
            ScriptType::P2WPKH | ScriptType::P2WSH => {
                //Mark input as Segwit
                builder.inputs[index].segwit = true;
                
                //Redeem script goes into the scriptSig
                let mut script_sig: Vec<u8> = vec![x.code.len() as u8];
                script_sig.append(&mut x.code.clone());
                builder.script_sigs[index] = Some(Script::new(script_sig));

                //Sign and create witness
                match x.determine_type() {
                    ScriptType::P2WPKH => p2wpkh(builder, tx_copy, index, sighash, x, &signing_data.keys[0])?,
                    ScriptType::P2WSH => p2wsh(builder, tx_copy, index, sighash, signing_data)?,
                    _ => panic!("Non standard P2SH segwit detected")
                }

                return Ok(())
            },

           /* Regular P2SH */
            _ => { 
                let mut tx_copy = tx_copy.clone();

                //Modify and get the hash preimage of the transaction                 //Create hashpreimage with the redeemscript
                let hash_preimage = hashpreimage::legacy(&mut tx_copy, sighash, index, &signing_data.script.clone().unwrap())?;

                //Create a signature for each private key provided. 
                //If none are provided, it will not do anything.
                let mut signatures: Vec<Signature> = vec![];
                let msg = match signature::new_msg(&hash::sha256d(&hash_preimage)) {
                    Ok(x) => x,
                    Err(_) => return Err(BuilderErr::FailedToCreateMessageStruct())
                };
                for i in 0..signing_data.keys.len() {
                    signatures.push(
                        signature::sign(&msg, &signing_data.keys[i].raw())
                    );
                }

                //Construct and store the scriptSig and sigHash
                let script_sig: Script = match Script::p2sh_multisig_unlocking(&signatures, signing_data, sighash) {
                    Ok(x) => x,
                    Err(_) => return Err(BuilderErr::RedeemScriptMissing())
                };
                builder.script_sigs[index] = Some(script_sig);
                builder.sighashes[index] = Some(sighash.clone());
                
                
                return Ok(())
            }
        },

        //If no redeem script is given
        _ =>  return Err(BuilderErr::RedeemScriptMissing())
    }
}

pub fn p2wsh(
    builder: &mut TxBuilder,
    tx_copy: &Tx,
    index: usize,
    sighash: &SigHash,
    signing_data: &SigningData
) -> Result<(), BuilderErr> {
    
    //Get the BIP143 defined hash preimage of the transaction and hash it
    //The scriptCode under this circumstance is derived from the redeemScript
    let witness_script = match &signing_data.script {
        Some(x) => x,
        None => return Err(BuilderErr::RedeemScriptMissing())
    };
    let script_code = hashpreimage::script_code(witness_script);
    let hash_preimage = hashpreimage::segwit(&builder.network, tx_copy, sighash, index, &script_code)?;
    let hash: [u8; 32] = hash::sha256d(hash_preimage);

    //Create a signature for each private key provided. 
    //If none are provided, it will not do anything.
    let mut signatures: Vec<Signature> = vec![];
    let msg = match signature::new_msg(&hash) {
        Ok(x) => x,
        Err(_) => return Err(BuilderErr::FailedToCreateMessageStruct())
    };
    for i in 0..signing_data.keys.len() {
        signatures.push(
            signature::sign(&msg, &signing_data.keys[i].raw())
        );
    }

    //Create the witness and store it and the sighash
    let witness: Witness = Witness::p2wsh(&signatures, &witness_script, sighash);
    builder.witness[index] = Some(witness);
    builder.sighashes[index] = Some(sighash.clone());

    
    Ok(())
}