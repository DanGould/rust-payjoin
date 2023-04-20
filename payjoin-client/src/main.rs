use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use bitcoincore_rpc::bitcoin::Amount;
use bitcoincore_rpc::RpcApi;
use clap::{arg, Arg, Command};
use payjoin::bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use payjoin::receiver::PayjoinProposal;
use payjoin::{PjUriExt, UriExt};
use rouille::{Request, Response};

fn main() -> Result<()> {
    env_logger::init();

    let matches = cli().get_matches();
    let port = matches.get_one::<String>("PORT").context("Missing PORT argument")?;
    let rpc_user =
        matches.get_one::<String>("BITCOIN_RPC_USER").context("Missing BITCOIN_RPC_USER argument")?;
    let rpc_pass =
        matches.get_one::<String>("BITCOIN_RPC_PASS").context("Missing BITCOIN_RPC_PASS argument")?;
    let bitcoind = bitcoincore_rpc::Client::new(
        &format!(
            "http://127.0.0.1:{}",
            port.parse::<u16>().context("Failed to parse PORT argument")?
        ),
        bitcoincore_rpc::Auth::UserPass(rpc_user.into(), rpc_pass.into()),
    )
    .context("Failed to connect to bitcoind")?;
    match matches.subcommand() {
        Some(("send", sub_matches)) => {
            let bip21 = sub_matches.get_one::<String>("BIP21").context("Missing BIP21 argument")?;
            let danger_accept_invalid_certs =
                match { sub_matches.get_one::<String>("DANGER_ACCEPT_INVALID_CERTS") } {
                    Some(danger_accept_invalid_certs) =>
                        bool::from_str(danger_accept_invalid_certs).unwrap_or(false),
                    None => false,
                };
            send_payjoin(bitcoind, bip21, danger_accept_invalid_certs)?;
        }
        Some(("receive", sub_matches)) => {
            let amount =
                sub_matches.get_one::<String>("AMOUNT").context("Missing AMOUNT argument")?;
            let endpoint =
                sub_matches.get_one::<String>("ENDPOINT").context("Missing ENDPOINT argument")?;
            receive_payjoin(bitcoind, amount, endpoint)?;
        }
        _ => unreachable!(), // If all subcommands are defined above, anything else is unreachabe!()
    }

    Ok(())
}

fn send_payjoin(
    bitcoind: bitcoincore_rpc::Client,
    bip21: &str,
    danger_accept_invalid_certs: bool,
) -> Result<()> {
    let link = payjoin::Uri::try_from(bip21)
        .map_err(|e| anyhow!("Failed to create URI from BIP21: {}", e))?;

    let link = link
        .check_pj_supported()
        .map_err(|e| anyhow!("The provided URI doesn't support payjoin (BIP78): {}", e))?;

    let amount = link
        .amount
        .ok_or(anyhow!("please specify the amount in the Uri"))
        .map(|amt| Amount::from_sat(amt.to_sat()))?;
    let mut outputs = HashMap::with_capacity(1);
    outputs.insert(link.address.to_string(), amount);

    let options = bitcoincore_rpc::json::WalletCreateFundedPsbtOptions {
        lock_unspent: Some(true),
        fee_rate: Some(Amount::from_sat(2000)),
        ..Default::default()
    };
    let psbt = bitcoind
        .wallet_create_funded_psbt(
            &[], // inputs
            &outputs,
            None, // locktime
            Some(options),
            None,
        )
        .context("Failed to create PSBT")?
        .psbt;
    let psbt = bitcoind
        .wallet_process_psbt(&psbt, None, None, None)
        .with_context(|| "Failed to process PSBT")?
        .psbt;
    let psbt = load_psbt_from_base64(psbt.as_bytes())
        .with_context(|| "Failed to load PSBT from base64")?;
    log::debug!("Original psbt: {:#?}", psbt);
    let pj_params = payjoin::sender::Configuration::with_fee_contribution(
        payjoin::bitcoin::Amount::from_sat(10000),
        None,
    );
    let (req, ctx) = link
        .create_pj_request(psbt, pj_params)
        .with_context(|| "Failed to create payjoin request")?;
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(danger_accept_invalid_certs)
        .build()
        .with_context(|| "Failed to build reqwest http client")?;
    let response = client
        .post(req.url)
        .body(req.body)
        .header("Content-Type", "text/plain")
        .send()
        .with_context(|| "HTTP request failed")?;
    // TODO display well-known errors and log::debug the rest
    let psbt = ctx.process_response(response).with_context(|| "Failed to process response")?;
    log::debug!("Proposed psbt: {:#?}", psbt);
    let psbt = bitcoind
        .wallet_process_psbt(&serialize_psbt(&psbt), None, None, None)
        .with_context(|| "Failed to process PSBT")?
        .psbt;
    let tx = bitcoind
        .finalize_psbt(&psbt, Some(true))
        .with_context(|| "Failed to finalize PSBT")?
        .hex
        .ok_or_else(|| anyhow!("Incomplete PSBT"))?;
    let txid =
        bitcoind.send_raw_transaction(&tx).with_context(|| "Failed to send raw transaction")?;
    log::info!("Transaction sent: {}", txid);
    Ok(())
}

fn receive_payjoin(
    bitcoind: bitcoincore_rpc::Client,
    amount_arg: &str,
    endpoint_arg: &str,
) -> Result<()> {
    use payjoin::Uri;

    let pj_receiver_address = bitcoind.get_new_address(None, None)?;
    let amount = Amount::from_sat(amount_arg.parse()?);
    let pj_uri_string = format!(
        "{}?amount={}&pj={}",
        pj_receiver_address.to_qr_uri(),
        amount.to_btc(),
        endpoint_arg
    );
    let pj_uri = Uri::from_str(&pj_uri_string)
        .map_err(|e| anyhow!("Constructed a bad URI string from args: {}", e))?;
    let _pj_uri = pj_uri
        .check_pj_supported()
        .map_err(|e| anyhow!("Constructed URI does not support payjoin: {}", e))?;

    println!("Awaiting payjoin at BIP 21 Payjoin Uri:");
    println!("{}", pj_uri_string);

    rouille::start_server("0.0.0.0:3000", move |req| handle_web_request(&req, &bitcoind));
}

fn handle_web_request(req: &Request, bitcoind: &bitcoincore_rpc::Client) -> Response {
    handle_payjoin_request(req, bitcoind)
        .map_err(|e| match e {
            ReceiveError::RequestError(e) => {
                log::error!("Error handling request: {}", e);
                Response::text(e.to_string()).with_status_code(400)
            }
            e => {
                log::error!("Error handling request: {}", e);
                Response::text(e.to_string()).with_status_code(500)
            }
        })
        .unwrap_or_else(|err_resp| err_resp)
}

fn handle_payjoin_request(
    req: &Request,
    bitcoind: &bitcoincore_rpc::Client,
) -> Result<Response, ReceiveError> {
    use bitcoin::hashes::hex::ToHex;

    let headers = Headers(req.headers());
    let proposal = payjoin::receiver::UncheckedProposal::from_request(
        req.data().context("Failed to read request body")?,
        req.raw_query_string(),
        headers,
    )?;

    // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
    let _to_broadcast_in_failure_case = proposal.get_transaction_to_schedule_broadcast();

    // The network is used for checks later
    let network = match bitcoind.get_blockchain_info()?.chain.as_str() {
        "main" => bitcoin::Network::Bitcoin,
        "test" => bitcoin::Network::Testnet,
        "regtest" => bitcoin::Network::Regtest,
        _ => return Err(ReceiveError::Other(anyhow!("Unknown network"))),
    };

    // Receive Check 1: Can Broadcast
    let proposal = proposal.check_can_broadcast(|tx| {
        bitcoind
            .test_mempool_accept(&[bitcoin::consensus::encode::serialize(&tx).to_hex()])
            .unwrap()
            .first()
            .unwrap()
            .allowed
    })?;
    log::trace!("check1");

    // Receive Check 2: receiver can't sign for proposal inputs
    let proposal = proposal.check_inputs_not_owned(|input| {
        let address = bitcoin::Address::from_script(&input, network).unwrap();
        bitcoind.get_address_info(&address).unwrap().is_mine.unwrap()
    })?;
    log::trace!("check2");
    // Receive Check 3: receiver can't sign for proposal inputs
    let proposal = proposal.check_no_mixed_input_scripts()?;
    log::trace!("check3");

    // Receive Check 4: have we seen this input before? More of a check for non-interactive i.e. payment processor receivers.
    let mut payjoin = proposal
        .check_no_inputs_seen_before(|_| false)
        .unwrap()
        .identify_receiver_outputs(|output_script| {
            let address = bitcoin::Address::from_script(&output_script, network).unwrap();
            bitcoind.get_address_info(&address).unwrap().is_mine.unwrap()
        })?;
    log::trace!("check4");

    // Select receiver payjoin inputs.
    _ = try_contributing_inputs(&mut payjoin, bitcoind)
        .map_err(|e| log::warn!("Failed to contribute inputs: {}", e));

    let receiver_substitute_address = bitcoind.get_new_address(None, None)?;
    payjoin.substitute_output_address(receiver_substitute_address);

    let payjoin_proposal_psbt = payjoin.apply_fee(Some(1))?;

    log::debug!("Extracted PSBT: {:#?}", payjoin_proposal_psbt);
    // Sign payjoin psbt
    let payjoin_base64_string =
        base64::encode(bitcoin::consensus::serialize(&payjoin_proposal_psbt));
    // `wallet_process_psbt` adds available utxo data and finalizes
    let payjoin_proposal_psbt =
        bitcoind.wallet_process_psbt(&payjoin_base64_string, None, None, Some(false))?.psbt;
    let payjoin_proposal_psbt =
        load_psbt_from_base64(payjoin_proposal_psbt.as_bytes()).context("Failed to parse PSBT")?;
    let payjoin_proposal_psbt = payjoin.prepare_psbt(payjoin_proposal_psbt)?;
    log::debug!("Receiver's PayJoin proposal PSBT Rsponse: {:#?}", payjoin_proposal_psbt);

    let payload = base64::encode(bitcoin::consensus::serialize(&payjoin_proposal_psbt));
    log::info!("successful response");
    Ok(Response::text(payload))
}

fn try_contributing_inputs(
    payjoin: &mut PayjoinProposal,
    bitcoind: &bitcoincore_rpc::Client,
) -> Result<()> {
    use bitcoin::OutPoint;

    let available_inputs = bitcoind
        .list_unspent(None, None, None, None, None)
        .context("Failed to list unspent from bitcoind")?;
    let candidate_inputs: HashMap<Amount, OutPoint> = available_inputs
        .iter()
        .map(|i| (i.amount, OutPoint { txid: i.txid, vout: i.vout }))
        .collect();

    let selected_outpoint = payjoin.try_preserving_privacy(candidate_inputs).expect("gg");
    let selected_utxo = available_inputs
        .iter()
        .find(|i| i.txid == selected_outpoint.txid && i.vout == selected_outpoint.vout)
        .context("This shouldn't happen. Failed to retrieve the privacy preserving utxo from those we provided to the seclector.")?;
    log::debug!("selected utxo: {:#?}", selected_utxo);

    //  calculate receiver payjoin outputs given receiver payjoin inputs and original_psbt,
    let txo_to_contribute = bitcoin::TxOut {
        value: selected_utxo.amount.to_sat(),
        script_pubkey: selected_utxo.script_pub_key.clone(),
    };
    let outpoint_to_contribute =
        bitcoin::OutPoint { txid: selected_utxo.txid, vout: selected_utxo.vout };
    payjoin.contribute_witness_input(txo_to_contribute, outpoint_to_contribute);
    Ok(())
}

enum ReceiveError {
    RequestError(payjoin::receiver::RequestError),
    BitcoinRpc(bitcoincore_rpc::Error),
    Other(anyhow::Error),
}

impl fmt::Display for ReceiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReceiveError::RequestError(e) => write!(f, "RequestError: {}", e),
            ReceiveError::BitcoinRpc(e) => write!(f, "BitcoinRpc: {}", e),
            ReceiveError::Other(e) => write!(f, "Other: {}", e),
        }
    }
}

impl From<payjoin::receiver::RequestError> for ReceiveError {
    fn from(e: payjoin::receiver::RequestError) -> Self { ReceiveError::RequestError(e) }
}

impl From<bitcoincore_rpc::Error> for ReceiveError {
    fn from(e: bitcoincore_rpc::Error) -> Self { ReceiveError::BitcoinRpc(e) }
}

impl From<anyhow::Error> for ReceiveError {
    fn from(e: anyhow::Error) -> Self { ReceiveError::Other(e) }
}

struct Headers<'a>(rouille::HeadersIter<'a>);
impl payjoin::receiver::Headers for Headers<'_> {
    fn get_header(&self, key: &str) -> Option<&str> {
        let mut copy = self.0.clone(); // lol
        copy.find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v)
    }
}

fn load_psbt_from_base64(
    mut input: impl std::io::Read,
) -> Result<Psbt, payjoin::bitcoin::consensus::encode::Error> {
    use payjoin::bitcoin::consensus::Decodable;

    let mut reader = base64::read::DecoderReader::new(
        &mut input,
        base64::Config::new(base64::CharacterSet::Standard, true),
    );
    Psbt::consensus_decode(&mut reader)
}

fn serialize_psbt(psbt: &Psbt) -> String {
    use payjoin::bitcoin::consensus::Encodable;

    let mut encoder = base64::write::EncoderWriter::new(Vec::new(), base64::STANDARD);
    psbt.consensus_encode(&mut encoder)
        .expect("Vec doesn't return errors in its write implementation");
    String::from_utf8(
        encoder.finish().expect("Vec doesn't return errors in its write implementation"),
    )
    .unwrap()
}

fn cli() -> Command {
    Command::new("payjoin")
        .about("Transfer bitcoin and preserve your privacy")
        .arg(arg!(<PORT> "The port of the bitcoin node"))
        .arg_required_else_help(true)
        .arg(arg!(<BITCOIN_RPC_USER> "Path to the rpc user of the bitcoin node"))
        .subcommand_required(true)
        .arg(arg!(<BITCOIN_RPC_PASS> "Path to the rpc password file of the bitcoin node"))
        .subcommand_required(true)
        .subcommand(
            Command::new("send")
                .arg_required_else_help(true)
                .arg(arg!(<BIP21> "The `bitcoin:...` payjoin uri to send to"))
                .arg(Arg::new("DANGER_ACCEPT_INVALID_CERTS").hide(true).help("Wicked dangerous! Vulnerable to MITM attacks! Accept invalid certs for the payjoin endpoint")),
        )
        .subcommand(
            Command::new("receive")
                .arg_required_else_help(true)
                .arg(arg!(<AMOUNT> "The amount to receive in satoshis"))
                .arg_required_else_help(true)
                .arg(arg!(<ENDPOINT> "The `pj=` endpoint to receive the payjoin request")),
        )
}
