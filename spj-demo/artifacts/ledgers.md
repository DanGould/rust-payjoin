# Spam gauntlet ledgers

## (a) board garbage

|                                       |            |
| ------------------------------------- | ---------- |
| attacker: unworked posts rejected     | 8 / 8      |
| attacker: worked posts admitted       | 12 / 12    |
| attacker: hashes burned for admission | 31547      |
| receiver: blobs scanned               | 13         |
| receiver: bytes downloaded            | 6656       |
| receiver: scan time                   | 9.048727ms |
| receiver: real notifications found    | 1          |

## (b) addressed garbage

|                                    |             |
| ---------------------------------- | ----------- |
| attacker: garbage frames injected  | 6           |
| receiver: frames trial-decrypted   | 7           |
| receiver: drain time               | 45.102462ms |
| receiver: real proposals recovered | 1           |

## (c) valid-decoy probe

|                                          |                |
| ---------------------------------------- | -------------- |
| attacker: probe cost (spent to receiver) | 0.30000000 BTC |
| receiver: on-chain revenue               | 0.30000000 BTC |
| attacker: re-probes of the same coin     | 1              |
| receiver: re-probes dropped by dedupe    | 1              |

## (f) board-cap flood

|                                    |                                     |
| ---------------------------------- | ----------------------------------- |
| attacker: board posts to reach cap | 7                                   |
| attacker: hashes burned            | 29112                               |
| attacker: regtest coin cost        | 0 (free on regtest)                 |
| honest sender: board post status   | 503                                 |
| honest sender: payment outcome     | completed as vanilla silent payment |
| payments failed                    | 0                                   |
