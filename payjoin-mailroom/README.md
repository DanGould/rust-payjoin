# Payjoin Mailroom

payjoin-mailroom is a single, lightweight binary that bundles the two server-side roles required by BIP 77 Async Payjoin:

- **Payjoin Directory**: a store-and-forward mailbox that holds small, ephemeral, end-to-end encrypted payloads so a sender and receiver can complete a payjoin asynchronously (they don't need to be online at the same time).
- **OHTTP Relay**: an [Oblivious HTTP](https://en.wikipedia.org/wiki/Oblivious_HTTP) proxy that separates client IP addresses from the directory, preventing the directory from correlating users with their network identity.

Note that this binary is under active development and thus the CLI and configuration file may be unstable.

## Deployment

### How the two roles work together

The relay and directory serve different purposes in BIP 77's privacy design:

- The **relay** sees client IP addresses but cannot read message contents.
- The **directory** stores and forwards messages but cannot see client IPs.

OHTTP keeps these two views separate. Neither role alone has enough information to link a user's network identity to their payjoin session.

### What an operator can see

The operator holds no keys and sees no Bitcoin addresses. Every payload is encrypted end to end between sender and receiver, so the directory stores ciphertext it cannot open. The directory sees encrypted mailboxes but no client IPs. The relay sees client IPs but no content. Neither role can tell which sender is paying which receiver. Running both roles on one host does not change this, because the relay only forwards to other operators' directories.

### Retention

A mailbox and its payload stay on disk until the mailbox expires. The default is 7 days, set by `mailbox_ttl` in seconds. Reading a payload does not delete it. Expired mailboxes are pruned as soon as they expire so that stale mailboxes cannot be enumerated. V1 (BIP 78) requests are never written to disk and are held in memory only while the sender's request is open.

### Running both roles in one process

Running a single `payjoin-mailroom` binary is the simplest deployment. The binary bundles both roles and includes a built-in **sentinel tag** that prevents the relay from looping requests back to its own directory. This means a single-process deployment still enforces the privacy separation: the relay component forwards to _other_ directories, not to itself.

### Connecting to other operators

In production, each `payjoin-mailroom` instance connects to directories and relays run by other operators. BIP 77's `allowed_purposes` mechanism lets any relay forward to any directory that advertises BIP 77 support, so operators do not need to coordinate pairings. The more independent operators participate, the harder it is for any single party to correlate users with their transactions.

### Operators who also ship a wallet

An operator that also ships a wallet must not default that wallet to its own directory when the wallet syncs through the operator's own Electrum, Esplora or mempool backend. The backend already sees the wallet's IP address and which transactions it asks about. If the same operator's directory then holds the wallet's mailbox, that operator can join the two views. Backend IP plus own mailbox is exactly the correlation the relay and directory split exists to prevent. Point the wallet at other operators' directories and use your own only as one option among many.

### V1 backwards compatibility

V1 (BIP 78) requests bypass OHTTP entirely. When V1 is enabled, the directory can see sender IP addresses and full transaction contents for V1 requests. V1 support exists for backwards compatibility with wallets that have not yet upgraded to V2. Operators who want the strongest privacy guarantees should disable the `[v1]` config section. See the [V1 Address Screening](#v1-address-screening) section for screening options when V1 is enabled.

## Operators

This table is the list of Payjoin mailroom operators. Wallets and other clients take their relay and directory choices from it. A wallet vendors a snapshot of the table at release time rather than fetching it at run time, so no install phones home to learn the list.

### Non-collusion

A session's relay and directory must be run by different operators. The relay sees client IPs and no content. The directory sees encrypted mailboxes and no IPs. If one party ran both, it could join the two views and tie a network identity to a payjoin session. A client must not pair a relay and a directory whose URLs share one registrable domain. Every operator below runs both roles from one mailroom URL, so its registrable domain identifies the operator.

Wallets should use every listed operator and pick a relay and a directory at random for each session. A wallet that uses only a few operators can be fingerprinted by the set it uses. Listing more independent directories does not shrink anyone's anonymity set when every wallet draws from the whole list.

An operator that also ships a wallet must not point that wallet at its own directory by default when the wallet syncs through the operator's own backend. Suppose a wallet ships with its vendor's Electrum server as the default backend and the vendor's directory as the default directory. The Electrum server sees the wallet's IP and the transactions it asks about. The directory sees the mailbox for the same payjoin. The vendor can join the two even though the relay hid the IP from the directory. See [Operators who also ship a wallet](#operators-who-also-ship-a-wallet).

### Listed operators

| Operator  | Country  | Mailroom                        | Version |
| --------- | -------- | ------------------------------- | ------- |
| Ava Chow  | US       | https://payjoin.achow101.com    | 0.1.2   |
| BOB Space | Thailand | https://pj.bobspacebkk.com      | 0.1.2   |
| Vinteum   | Brazil   | https://payjoin.lab.vinteum.org | 0.1.2   |

Each mailroom serves both roles from the one URL. Its OHTTP key configuration is at `/.well-known/ohttp-gateway` under that URL.

<!--
Row template. Copy the line below into the table and fill every column.
| Name | Country | https://mailroom.example.org | 0.1.2 |
-->

### Listing criteria

- Runs both roles, directory and relay, from one mailroom URL.
- Is run independently of every other listed operator, with no shared owners, staff or control.
- Shares no infrastructure with another entry. Two entries do not run on the same host or the same hosting account.
- Runs a payjoin-mailroom release no older than two minor versions behind the latest.
- Gives the Payjoin Foundation a security contact that answers.
- Consents to listing by opening the pull request that adds its row.

Coarse aggregate metrics, such as mailbox counts per operator domain, will become a listing requirement once the aggregate metrics export is ready. They are not required today.

The Payjoin Foundation curates this list against these criteria. Anyone can object to an entry on the pull request that adds or removes it.

### Delisting

An entry is removed when its mailroom has been unreachable for 30 days, when it runs a version with an unpatched security advisory, or when there is evidence that it colludes with another entry. Removal is a pull request against this file, so it happens in the open.

### How to get listed

Open a pull request against this file that adds a row to the table. Copy the row template from the comment under the table and fill every column. Open the pull request from an account that can speak for the operator. Opening it is your consent to be listed. Send your security contact to hello@payjoin.org. It is not published.

## Configuration

payjoin-mailroom reads configuration from `config.toml` (or the path given with `--config`). Every setting can also be supplied via environment variables prefixed with `PJ_`, using double underscores for nesting (e.g., `PJ_TELEMETRY__ENDPOINT`).

## Usage

### Cargo

```sh
cargo run
```

### Docker Compose

A simple [docker-compose.yml](docker-compose.yml) is provided for convenience.

```sh
docker compose up
```

### Nix

The rust-payjoin flake also provides `payjoin-mailroom` as a package.

```sh
nix run .#payjoin-mailroom -- --config payjoin-mailroom/config.toml
```

### systemd

```sh
# A minimal [payjoin-mailroom.example.service](payjoin-mailroom.example.service) unit file is provided for convenience. Edit paths and User= as your setup requires.
vim /etc/systemd/system/payjoin-mailroom.service
systemctl daemon-reload
systemctl enable --now payjoin-mailroom
```

## Telemetry

payjoin-mailroom supports **optional** OpenTelemetry-based telemetry (metrics).
Build with `--features telemetry` and configure via the [`[telemetry]`](config.example.com) config section.
When no telemetry configuration is present, it falls back to local-only console tracing.

## Access Control

Build with `--features access-control` to enable:

### IP Screening

Configured via the [`[access_control]`](config.example.toml) config section for IP- and region-based filtering.

The auto-fetched GeoLite2 database is provided by [MaxMind](https://www.maxmind.com) and distributed under the [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) license.

### V1 Address Screening

When the V1 protocol is enabled, payjoin-mailroom can screen PSBTs for blocked Bitcoin addresses.
Configure a local blocklist, a remote URL, or both via the [`[v1]`](config.example.toml) config section.
