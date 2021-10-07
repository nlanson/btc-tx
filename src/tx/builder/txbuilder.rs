/*
    Module that creates and signs transactions

    Todo:
        - Signing P2SH, P2WSH and P2WPKH inputs
            > P2SH and P2WSH need a *special* method that will take in as many keys and a redeemScript
            > P2WPKH will need to be signed using BIP-143 specification
*/
use crate::{
    tx::{
        Input,
        Output,
        Tx,
        Script,
        ScriptType
    },
    PrivKey,
    api,
    util::{
        Network,
        bytes
    },
    tx::Witness
};
use super::pipes;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
pub enum SigHash {
    ALL = 0x01,                 //All inputs and outputs are committed. 
    NONE = 0x02,                //All inputs are committed. No outputs.
    SINGLE = 0x03,              //All inputs and the output with the same index as the input being signed are committed.
    ALL_ANYONECANPAY = 0x81,    //Current input and all outputs are committed.
    NONE_ANYONECANPAY = 0x82,   //Current input and no outputs are committed.
    SINGLE_ANYONECANPAY = 0x83  //Current input and output with the same index are committed.
}

#[derive(Debug)]
pub struct TxBuilder {
    pub network: Network,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub script_sigs: Vec<Option<Script>>, //scriptSigs are stored in this attribute
    pub witness: Vec<Option<Witness>>,    //witnesses are stored in this attribute
    pub sighashes: Vec<Option<SigHash>>   //SigHash is stored to detect if new inputs/outputs can be added
}

#[derive(Clone)]
pub struct SigningData {
    pub keys: Vec<PrivKey>,
    pub script: Option<Script>
}

impl SigningData {
    pub fn new(keys: Vec<PrivKey>, script: Option<Script>) -> Self {
        Self {
            keys,
            script
        }
    }
}

#[derive(Debug)]
pub enum BuilderErr {
    CannotGetScriptPubKey(String, usize),
    FailedToSerialize(),
    FailedToCreateMessageStruct(),
    UnsignedInput(usize),
    OutputIndexMissing(usize),
    InvalidInputIndex(usize),
    UnknownScriptType(),
    TxCommitted(),
    CannotGetInputValue(),
    InvalidSigningData(),
    RedeemScriptMissing()
}

impl TxBuilder {
    pub fn new(network: Network) -> Self {
        Self {
            network,
            inputs: vec![],
            outputs: vec![],
            script_sigs: vec![],
            witness: vec![],
            sighashes: vec![]
        }
    }

    /**
        Add a new input from txid and output index
    */
    pub fn add_input(&mut self, txid: &str, vout: u32) -> Result<(), BuilderErr> {
        //Check if an input has been signed that does not allow for new inputs
        for i in 0..self.sighashes.len() {
            match self.sighashes[i] {
                Some(SigHash::ALL) |
                Some(SigHash::NONE) |
                Some(SigHash::SINGLE) => return Err(BuilderErr::TxCommitted()),
                _ => { /* New input can be added */}
            }
        }
        
        let txid_bytes: [u8; 32] = bytes::try_into(bytes::decode_02x(txid));
        let new_in: Input = Input::unsigned_input(txid_bytes, vout, 0xFFFFFFFF);
        self.inputs.push(new_in);
        self.script_sigs.push(None);
        self.witness.push(None);
        self.sighashes.push(None);

        Ok(())
    }

    /**
        Add a new output with recepeint address and value
    */
    pub fn add_output(&mut self, address: &str, value: u64) -> Result<(), BuilderErr> {
        //Check if an input has been signed that does not allow for new outputs
        for i in 0..self.sighashes.len() {
            match self.sighashes[i] {
                Some(SigHash::ALL) |
                Some(SigHash::ALL_ANYONECANPAY) => return Err(BuilderErr::TxCommitted()),
                _ => { /* New input can be added */}
            }
        }
        
        let new_out: Output = Output::new(address, value);
        self.outputs.push(new_out);

        Ok(())
    }

    /**
        Sign an input in the current transaction at the given index, key and sighash
    */  
    pub fn sign_input(&mut self, index: usize, signing_data: &SigningData, sighash: SigHash) -> Result<(), BuilderErr> {
        //Return an error if the given input index is larger than the total amount of inputs
        if self.inputs.len() < index {
            return Err(BuilderErr::InvalidInputIndex(index))
        }
        
        //Create a copy of the transaction
        let tx_copy: Tx = Tx::construct(self.inputs.clone(), self.outputs.clone(), 0, false);

        //Get the unlocking script type of the input
        let script_pub_key: Script = Script::new(Self::get_input_script_pub_key(&self, index)?);
        let input_script_type: ScriptType = script_pub_key.determine_type();
        match input_script_type {
                ScriptType::P2WPKH | ScriptType::P2WSH => self.inputs[index].segwit = true,
                _ => { }
        }
        
        //Sign the input and set the script_sig based on the locking script
        match input_script_type {
            ScriptType::P2PKH => {
                //Only sign p2pkh if 1 key is provided.
                if signing_data.keys.len() == 1 {
                    pipes::p2pkh(self, &tx_copy, index, &sighash, &script_pub_key, &signing_data.keys[0])?;
                } else {
                    return Err(BuilderErr::InvalidSigningData())
                }
            },
            ScriptType::P2WPKH => {
                //Only sign p2wpkh if 1 key is provided
                if signing_data.keys.len() == 1 {
                    pipes::p2wpkh(self, &tx_copy, index, &sighash, &script_pub_key, &signing_data.keys[0])?;
                } else {
                    return Err(BuilderErr::InvalidSigningData())
                }
            },
            ScriptType::P2SH => pipes::p2sh(self, &tx_copy, index, &sighash, &signing_data)?,
            ScriptType::P2WSH => pipes::p2wsh(self, &tx_copy, index, &sighash, &signing_data)?,
            ScriptType::NonStandard => return Err(BuilderErr::UnknownScriptType())
        }

        Ok(())
    }

    /**
        Get the scriptPubKey for the input being signed
    */
    fn get_input_script_pub_key(&self, index: usize) -> Result<Vec<u8> ,BuilderErr> {
        let rpc = api::JsonRPC::new(&self.network);
        let input_spkhex: Vec<u8> = match rpc.get_input_script_pub_key_hex(&bytes::encode_02x(&self.inputs[index].txid), self.inputs[index].vout) {
            Ok(x) => bytes::decode_02x(&x),
            Err(_) => return Err(BuilderErr::CannotGetScriptPubKey(bytes::encode_02x(&self.inputs[index].txid), index))
        };

        Ok(input_spkhex)
    }

    /**
        Take all the data in the Builder and make it into Tx that can be serialized
    */
    pub fn build(&self) -> Result<Tx, BuilderErr> {
        let version: u32 = 1;
        let input_count: usize = self.inputs.len();
        let output_count: usize = self.outputs.len();
        let locktime: u32 = 0x00000000;

        //Loop over each input and check if there is a scriptSig or witness for it
        let mut inputs: Vec<Input> = vec![];
        for i in 0..self.inputs.len() {
            match &self.script_sigs[i] {
                //Legacy or segwit
                //It will enter here if the input is legacy or P2SH nested Segwit
                Some(x) => {
                    //Put the stored scriptSig into the input
                    let mut input = self.inputs[i].clone();
                    input.scriptSig = x.clone();
                    input.scriptSig_size = input.scriptSig.len();

                    inputs.push(input);

                    //Witness data is created after this loop. 
                    //However, it could be brought into this loop
                    //to make the code more efficient.
                },

                //Unsigned or segwit
                //It will only enter here is the input is native Segwit
                None => {
                    //If input is segwit
                    if self.inputs[i].segwit {
                        //Remove the scriptSig
                        let mut input = self.inputs[i].clone();
                        input.scriptSig = Script::new(vec![]);
                        input.scriptSig_size = 0x00;
    
                        inputs.push(input);
                    } else {
                        //If there is no scriptSig and not marked as Segwit
                        return Err(BuilderErr::UnsignedInput(i))
                    }
                }
            }
        }

        //If any of the witnesses are present in the Tx, set the SegWit data
        let mut segwit: bool = false;
        let mut flag: Option<u8> = None;
        let mut marker: Option<u8> = None;
        let mut witness: Option<Vec<Witness>> = None;
        if self.witness.iter().any(|x| {
            match x {
                Some(_) => true,
                None => false
            }
        }) {
            let mut witnesses: Vec<Witness> = vec![];
            segwit = true;
            flag = Some(0x00);
            marker = Some(0x01);


            for i in 0..self.witness.len() {
                witnesses.push(
                    match &self.witness[i] {
                    Some(x) => x.clone(),
                    None => Witness::empty()
                    }
                );
            }

            witness = Some(witnesses);
        }
        
        
        //Return the Transaction
        Ok(Tx {
            version,
            flag,
            marker,
            input_count: input_count as u64,
            inputs,
            output_count: output_count as u64,
            outputs: self.outputs.clone(),
            witness,
            locktime,
            segwit
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        tx::Script
    };
    use btc_keyaddress::prelude::*;
    use btc_keyaddress::key::PrivKey as PrivKey;

    #[test]
    fn single_legacy_p2pkh_input() {
        let expected_txid = "d37c3d75e7a70261bf191dfc296272cbb20e0466167d4f6f8fde6c2458f05004";
        
        //Create and sign the transaction
        let mut txb = TxBuilder::new(Network::Testnet);
        txb.add_input("a8064a6143c6027dddafb356236a475dab3f56fa3dad1dc0c873e54e6527f167", 1).unwrap();
        txb.add_output("msSJzRfQb2T3hvws3vRhqtK2Ao39cabEa2", 80000).unwrap();

        let key: PrivKey = PrivKey::from_slice(&[25, 185, 89, 6, 72, 28, 43, 234, 167, 160, 163, 78, 240, 86, 146, 133, 49, 98, 255, 253, 45, 121, 146, 10, 233, 252, 142, 232, 193, 73, 255, 150]).unwrap();
        let signing_data = SigningData::new(vec![key], None);
        txb.sign_input(0, &signing_data, SigHash::ALL).unwrap();
        let tx: Tx = txb.build().unwrap();

        //Compare the derived and expected TXID
        assert_eq!(tx.get_txid(), expected_txid);
    }

    #[test]
    fn single_segwit_p2wpkh_input() {
        let expected_txid = "10296b2590ce4397a617cf77071581fc0eb34dc531b1c243565d7508970e57b7";
        
        //Create and sign the transaction
        let mut txb = TxBuilder::new(Network::Testnet);
        txb.add_input("36e336b364abaf48b46c415903b1d93c7a740d7a3bde1691e30fec3d7a180245", 0).unwrap();
        txb.add_output("tb1qj8rvxxnzkdapv3rueazzyn434duv5q5ep3ze5e", 60000).unwrap();
        
        let key: PrivKey = PrivKey::from_slice(&[131, 187, 80, 16, 233, 20, 231, 76, 171, 218, 189, 168, 220, 150, 47, 40, 73, 149, 85, 236, 159, 205, 198, 160, 182, 32, 149, 30, 95, 184, 54, 186]).unwrap();
        let signing_data = SigningData::new(vec![key], None);
        txb.sign_input(0, &signing_data, SigHash::ALL).unwrap();
        let tx: Tx = txb.build().unwrap();

        //Compare the derived and expected TXID
        assert_eq!(tx.get_txid(), expected_txid);
    }

    #[test]
    fn single_segwit_p2wpkh_input_and_2_outputs() {
        let expected_txid = "d8f1b1529a1f2db2ae09da0e8e5bc562dbdddc7647f8154d1f7d1360e2cde1c6";

        //Create and sign the transaction
        let mut txb = TxBuilder::new(Network::Testnet);
        txb.add_input("10296b2590ce4397a617cf77071581fc0eb34dc531b1c243565d7508970e57b7", 0).unwrap();
        txb.add_output("tb1qj8rvxxnzkdapv3rueazzyn434duv5q5ep3ze5e", 29000).unwrap();
        txb.add_output("tb1qj8rvxxnzkdapv3rueazzyn434duv5q5ep3ze5e", 29000).unwrap();
        
        let key: PrivKey = PrivKey::from_slice(&[131, 187, 80, 16, 233, 20, 231, 76, 171, 218, 189, 168, 220, 150, 47, 40, 73, 149, 85, 236, 159, 205, 198, 160, 182, 32, 149, 30, 95, 184, 54, 186]).unwrap();
        let signing_data = SigningData::new(vec![key], None);
        txb.sign_input(0, &signing_data, SigHash::ALL).unwrap();
        let tx: Tx = txb.build().unwrap();

        //Compare the derived and expected TXID
        assert_eq!(tx.get_txid(), expected_txid);
    }

    #[test]
    fn double_segwit_p2wpkh_inputs() {
        let expected_txid = "552af0fc08762799412d40c339c9c094981e353b161983c3e46b55b2a36dd8f0";

        //Create and sign the transaction
        let mut txb = TxBuilder::new(Network::Testnet);
        txb.add_input("d8f1b1529a1f2db2ae09da0e8e5bc562dbdddc7647f8154d1f7d1360e2cde1c6", 0).unwrap();
        txb.add_input("d8f1b1529a1f2db2ae09da0e8e5bc562dbdddc7647f8154d1f7d1360e2cde1c6", 1).unwrap();
        txb.add_output("tb1qj8rvxxnzkdapv3rueazzyn434duv5q5ep3ze5e", 50000).unwrap();

        let key: PrivKey = PrivKey::from_slice(&[131, 187, 80, 16, 233, 20, 231, 76, 171, 218, 189, 168, 220, 150, 47, 40, 73, 149, 85, 236, 159, 205, 198, 160, 182, 32, 149, 30, 95, 184, 54, 186]).unwrap();
        let signing_data = SigningData::new(vec![key], None);
        txb.sign_input(0, &signing_data, SigHash::SINGLE_ANYONECANPAY).unwrap();
        txb.sign_input(1, &signing_data, SigHash::ALL).unwrap();
        let tx: Tx = txb.build().unwrap();
        
        //Compare the derived and expected TXID
        assert_eq!(tx.get_txid(), expected_txid);
    }

    #[test]
    fn single_p2sh_1of1_input() {
        let expected_txid = "fd091c2594549f72c21d9c0541f6df660d47656f4b4a9898521884191a7c378a";

        //Create and sign the transaction
        let mut txb = TxBuilder::new(Network::Testnet);
        txb.add_input("34ab5526d94325a2bcd8bf5dc145c4af884ef6c6ca3ccb029a77ebe62d614f9e", 1).unwrap();
        txb.add_output("tb1qj8rvxxnzkdapv3rueazzyn434duv5q5ep3ze5e", 20000).unwrap();

        let key_1 = PrivKey::from_wif("cU1mPkyNgJ8ceLG5v2zN1VkZcvDCE7VK8KrnHwW82PZb6RCq7zRq").unwrap();
        let signing_data = SigningData::new(
            vec![key_1.clone()],
            Some(Script::multisig_locking(1, 1, &vec![key_1]))
        );
        txb.sign_input(0, &signing_data, SigHash::ALL).unwrap();
        let tx = txb.build().unwrap();

        //Compare the derived and expected TXID
        assert_eq!(tx.get_txid(), expected_txid);
    }

    #[test]
    fn single_p2sh_2of3_input() {
        let expected_txid = "9ea7d9fe33b083193098004f81ea0eb20964c244fe98c381043ea74e7b58c302";

        //Create and sign the transaction
        let mut txb = TxBuilder::new(Network::Testnet);
        txb.add_input("a0cbeea4127b77724bb960720d0523835f66fced18ac6b315e6dc3d1daf49ce2", 0).unwrap();
        txb.add_output("tb1qj8rvxxnzkdapv3rueazzyn434duv5q5ep3ze5e", 20000).unwrap();

        let keys = vec![
            PrivKey::from_wif("cU1mPkyNgJ8ceLG5v2zN1VkZcvDCE7VK8KrnHwW82PZb6RCq7zRq").unwrap(),
            PrivKey::from_wif("cPTFNJD7hgbZTqNJgW89HABGtRzYo5aLpCQKvmNdtRNGWo49NAky").unwrap(),
            PrivKey::from_wif("cNUe2L9CNJZoedMU8YNrzRuxFc56dvMjFxzK4mTsSGhXwbidAyog").unwrap(),
        ];
        let signing_data = SigningData::new(
            vec![keys[0].clone(), keys[1].clone()],
            Some(Script::multisig_locking(2, 3, &keys))
        );
        txb.sign_input(0, &signing_data, SigHash::ALL).unwrap();
        let tx = txb.build().unwrap();

        //Compare the derived and expected TXID
        assert_eq!(tx.get_txid(), expected_txid);
    }

    #[test]
    fn single_p2sh_nested_p2wpkh_input() {
        let expected_txid = "bd0f713f118533f77f097e3280eae4b57fca9f9d97ed40d091c520ce989a4886";
        
        //Create and sign the transaction
        let mut txb = TxBuilder::new(Network::Testnet);
        txb.add_input("3d0b0b9ccc50efa160ac4d69be18b1c4f4b72c4aed55645c0fb7edfe5dc7e7c7", 0).unwrap();
        txb.add_output("2NChp1fpJkEn5vRjXK6gKPgwbBi3TAVvTKX", 95000).unwrap();

        let key = PrivKey::from_wif("cQTQNYrAbwZN6RDuxL4C9WMH8JBNfVPKVwFJtVqCksgjmHTWdtCR").unwrap();
        let signing_data = SigningData::new(
            vec![key.clone()],
            Some(Script::p2sh_p2wpkh_redeem_script(&key))
        );
        txb.sign_input(0, &signing_data, SigHash::ALL).unwrap();
        let tx: Tx = txb.build().unwrap();

        //Compare the derived and expected TXID
        assert_eq!(tx.get_txid(), expected_txid);
    }

    #[test]
    fn single_p2wsh_2of3_input() {
        let expected_txid = "8963a59c51bd41771d83cbcb0094bc313bd00e28a610ee3b022a2dcdb9e2bea6";
        
        //Create and sign the transaction
        let mut txb = TxBuilder::new(Network::Testnet);
        txb.add_input("45336930c71d04e44361de5dcb289fc24ecaf4591db8fd1105157c7310aee441", 1).unwrap();
        txb.add_output("tb1qk0ns5zr0xgydqyyzs65sq9lrygl4336gznw4pd7cl0vhf3qww8nsymgaqm", 95000).unwrap();

        let keys = vec![
            PrivKey::from_wif("cPUFTUmN7R1vqyGetUfEv8Az5vTNAipHyCLZq8kpJS355NmB44BJ").unwrap(),
            PrivKey::from_wif("cNReSU1dagjXPo4ky99PaXbW4NobKWoppb5AVaCpjjQsJ2uRgoDe").unwrap(),
            PrivKey::from_wif("cSTgRcaiVDpG4yrsECW59wfUwYjTYsHh4UCcUhz2WatYWd18KDso").unwrap()
        ];
        let signing_data = SigningData::new(
            vec![keys[0].clone(), keys[1].clone()],
            Some(Script::multisig_locking(2, 3, &keys))
        );
        txb.sign_input(0, &signing_data, SigHash::ALL).unwrap();
        let tx: Tx = txb.build().unwrap();

        //Compare the derived and expected TXID
        assert_eq!(tx.get_txid(), expected_txid);
    }
}