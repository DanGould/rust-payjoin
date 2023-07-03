<div align="center">
  <h1>payjoin-cli</h1>

  <p>
    <strong>A command-line payjoin client for bitcoind in pure rust</strong>
  </p>
</div>

## About

This project provides a command line payjoin client application using the latest [Payjoin APIs](https://docs.rs/payjoin/latest/payjoin) to send and receive [BIP 78](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki) payjoins.

If you are considering using BDK in your own wallet project bdk-cli is a nice playground to get started with. It allows easy testnet and regtest wallet operations, to try out what's possible with descriptors, miniscript, and BDK APIs. For more information on BDK refer to the [website](https://bitcoindevkit.org/) and the [rust docs](https://docs.rs/bdk/latest/bdk/index.html)

If you are considering using payjoin in your own wallet project payjoin-cli is a nice playground to get started with. It allows easy testnet and regtest payjoin operations to try out what's possible. For more information on payjoin refer to the [website](https://payjoin.org) and the [rust docs](https://docs.rs/payjoin/latest/payjoin/index.html).

## Install payjoin-cli

<!-- ### From source

To install a dev version of `payjoin-cli` from a local git repo:

```shell
cd <payjoin-cli git repo directory>
cargo install --path .
payjoin-cli help # to verify it worked
``` -->

Get a list of commands and options:

```shell
RUST_LOG=debug cargo run -- --help
```

Running payjoin-cli will create a `config.toml` file where you can persist options.

e.g.

```toml
# config.toml

bitcoind_cookie = "/Users/ubuntu/.polar/networks/1/volumes/bitcoind/backend2/regtest/.cookie"
bitcoind_rpchost="http://localhost:18445"

```

## Receive payjoin

Where "receiver" is the name of your funded regtest wallet and you wish to request 888888 sats

```shell
RUST_LOG=debug cargo run  -- -r localhost:18332/wallets/receiver receive 888888
```

The output will include a payjoin capable bip21 uri:

```shell
BITCOIN:BCRT1QEN6W9G3ENDHVQ3RN7MURZU2K4ZCSFV9UJQNX60?amount=0.00888888&pj=https://localhost:3010
```

The default configuration listens for payjoin requests at `http://localhost:3000` and lists the server as `https://localhost:3010`. Only `https` and `.onion` payjoin endpoints are valid. Therefore, in order to receive payjoin, one must also host an https reverse proxy to marshall https requests from `localhost:3010` to `localhost:3000`. An easy way to set this up for testing is with [`local-ssl-proxy`](https://github.com/cameronhunter/local-ssl-proxy). An nginx configuration for an https reverse-proxy can be found [here in the nolooking LND payjoin server tests](https://github.com/chaincase-app/nolooking/blob/master/tests/compose/nginx/reverse-https-proxy.conf).

### ⚠️ Local testing may require one more option

The DANGER_ACCEPT_INVALID_CERTS option must be present to use self signed certificates not added to the root store. You should think very carefully before using this option. If invalid certificates are trusted, any certificate for any site will be trusted for use. This includes expired certificates. **This introduces significant vulnerabilities, and should only be used as a last resort.**

## Send payjoin

Run the payjoin-cli from **a directory separate from the receiver**. This should be configured with a separate rpchost to connect to a separate sender wallet. Once the reverse proxy is running, just paste a BIP 21 supporting payjoin following the send subcommand.

```shell
RUST_LOG=debug cargo run  -- send "BITCOIN:BCRT1QEN6W9G3ENDHVQ3RN7MURZU2K4ZCSFV9UJQNX60?amount=0.00888888&pj=https://localhost:3010"
```
