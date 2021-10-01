use crate::{
    tx::Script,
    tx::SigHash,
    tx::Tx,
    tx::TxBuilder,
    util::serialize::Serialize,
    util::Network,
    util::bytes,
    hash,
    api
};
use super::BuilderErr;

/**
    Create the hash preimage for legacy transactions
*/  
pub fn legacy(
    tx_copy: &mut Tx,
    sighash: &SigHash,
    index: usize
) -> Result<Vec<u8>, BuilderErr> {
    match sighash {
        SigHash::ALL => { 
            /*No need to modify txdata for sighash_all*/ 
        },
        SigHash::NONE => {
            //Remove all outputs and set output count to 0
            tx_copy.output_count = 0x00;
            tx_copy.outputs = vec![];
        },
        SigHash::SINGLE => {
            //Remove all outputs apart from the output at the same index as the input being signed
            if tx_copy.outputs.len() > index {
                tx_copy.outputs = vec![tx_copy.outputs[index].clone()];
                tx_copy.output_count = 0x01;
            } else {
                return Err(BuilderErr::OutputIndexMissing(index))
            }
        },
        SigHash::ALL_ANYONECANPAY => {
            //Remove all inputs apart from the one being signed
            tx_copy.inputs = vec![tx_copy.inputs[index].clone()];
            tx_copy.input_count = 0x01;
        },
        SigHash::NONE_ANYONECANPAY => {
            //Remove all inputs apart from the one being signed
            tx_copy.inputs = vec![tx_copy.inputs[index].clone()];
            tx_copy.input_count = 0x01;

            //Remove all outputs and set output count to 0
            tx_copy.output_count = 0x00;
            tx_copy.outputs = vec![];
        },
        SigHash::SINGLE_ANYONECANPAY => {
            //Remove all inputs apart from the one being signed
            tx_copy.inputs = vec![tx_copy.inputs[index].clone()];
            tx_copy.input_count = 0x01;

            //Remove all outputs apart from the output at the same index as the input being signed
            if tx_copy.outputs.len() > index {
                tx_copy.outputs = vec![tx_copy.outputs[index].clone()];
                tx_copy.output_count = 0x01;
            } else {
                return Err(BuilderErr::OutputIndexMissing(index))
            }
        }
    }

    Ok(match tx_copy.serialize() {
        Ok(x) => { 
            let mut x = x.clone();
            x.append(&mut (sighash.clone() as u32).to_le_bytes().to_vec());
            x 
        },
        Err(_) => return Err(BuilderErr::FailedToSerialize())
    })
}

/**
    Create the hash preimage for legacy transactions.
    BIP-143
*/
pub fn segwit(
    network: &Network,
    tx_copy: &Tx,
    sighash: &SigHash,
    index: usize,
    script_code: &Script
) -> Result<Vec<u8>, BuilderErr> {
    let n_version = tx_copy.version.to_le_bytes();
    
    //hashPrevouts is the SHA256D of all input outpoints if ANYONECANPAY is not set
    //If ANYONECANPAY is set, hashPrevOuts is [0; 32]
    let hash_prevouts: [u8; 32] = match sighash {
        SigHash::ALL | SigHash::NONE | SigHash::SINGLE
        => {
            let mut outpoints = vec![];
            for i in 0..tx_copy.inputs.len() {
                outpoints.append(&mut bytes::reverse(&tx_copy.inputs[i].txid.to_vec()));
                outpoints.append(&mut tx_copy.inputs[i].vout.to_le_bytes().to_vec());
            }
            hash::sha256d(outpoints)
        },
        
        _ => [0; 32]
    };

    //hashSequence is the SHA256D of of the sequence of all inputs if ANYONECANPAY, NONE or SINGLE are not set.
    //else it is [0; 32]
    let hash_sequence: [u8; 32] = match sighash {
        SigHash::ALL => {
            let mut sequences = vec![];
            for i in 0..tx_copy.inputs.len() {
                sequences.append(&mut tx_copy.inputs[i].sequence.to_le_bytes().to_vec());
            }
            hash::sha256d(sequences)
        },
        
        _ => [0; 32]
    };

    //hashOutputs is the SHA256D of all outputs if SigHash is not single, [0; 32] is SigHash is none
    //and the output at the same index as the input being signed if the SigHash is single.
    let hash_outputs: [u8; 32] = match sighash {
        SigHash::SINGLE => {
            if index >= tx_copy.outputs.len() { return Err(BuilderErr::OutputIndexMissing(index)) }
            let mut output = vec![];
            output.append(&mut tx_copy.outputs[index].serialize().unwrap());
            hash::sha256d(output)
        },
        SigHash::NONE => [0; 32],
        _ => {
            let mut outputs = vec![];
            for i in 0..tx_copy.outputs.len() {
                outputs.append(&mut tx_copy.outputs[index].serialize().unwrap());
            }
            hash::sha256d(outputs)
        },
    };

    let input_value: u64 = match api::JsonRPC::new(network).get_input_value(&bytes::encode_02x(&tx_copy.inputs[index].txid), tx_copy.inputs[index].vout){
        Ok(x) => x,
        Err(_) => return Err(BuilderErr::CannotGetInputValue())
    };

    let mut script_code = script_code.code.clone();
    script_code.remove(0);
    script_code.remove(0);
    script_code.splice(0..0, vec![0x19, 0x76, 0xa9, 0x14]);
    script_code.append(&mut vec![0x88, 0xac]);

    let mut outpoint: Vec<u8> = vec![];
    outpoint.append(&mut bytes::reverse(&tx_copy.inputs[index].txid.to_vec()));
    outpoint.append(&mut tx_copy.inputs[index].vout.to_le_bytes().to_vec());


    let mut bip143_prehash_serialization: Vec<u8> = vec![];
    bip143_prehash_serialization.append(&mut n_version.to_vec());                                        //version
    bip143_prehash_serialization.append(&mut hash_prevouts.to_vec());                                    //hashPrevout
    bip143_prehash_serialization.append(&mut hash_sequence.to_vec());                                    //hashSequence
    bip143_prehash_serialization.append(&mut outpoint);
    bip143_prehash_serialization.append(&mut script_code);                                               //scriptCode of the input
    bip143_prehash_serialization.append(&mut input_value.to_le_bytes().to_vec());                        //Input value
    bip143_prehash_serialization.append(&mut tx_copy.inputs[index].sequence.to_le_bytes().to_vec());     //Input sequence
    bip143_prehash_serialization.append(&mut hash_outputs.to_vec());                                     //hashOutputs
    bip143_prehash_serialization.append(&mut tx_copy.locktime.to_le_bytes().to_vec());                   //Locktime of the transaction
    let sh: u32 = match sighash {
        SigHash::ALL => 0x01,
        SigHash::NONE => 0x02,
        SigHash::SINGLE => 0x03,
        SigHash::ALL_ANYONECANPAY => 0x81,
        SigHash::NONE_ANYONECANPAY => 0x82,
        SigHash::SINGLE_ANYONECANPAY => 0x83
    };
    bip143_prehash_serialization.append(&mut sh.to_le_bytes().to_vec());                                 //Sighash

    

    Ok(bip143_prehash_serialization)
}