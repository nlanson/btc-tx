/*
    API module to make http requests to the Bitcoin JSON RPC

    Main net transactions to source data from local Bitcoin Core (Umbrel)
    Test net transaction to source data from https://testnet.bitcoinexplorer.org/ 
*/

#[tokio::main]
pub async fn get_tx(txid: &str) -> Result<(), ()> {
    let url = &format!("https://testnet.bitcoinexplorer.org/api/tx/{}", txid)[..];
    let body = match reqwest::get(url).await {
        Ok(x) => match x.text().await {
            Ok(x) => x,
            Err(_) => return Err(())
        },
        Err(_) => return Err(())
    };

    println!("{}", body);

    //need to parse body and extract relevant data

    Ok(())
}