# Demo cost ledgers

## (a) board garbage

|                                       |            |
| ------------------------------------- | ---------- |
| attacker: unworked posts rejected     | 8 / 8      |
| attacker: worked posts admitted       | 12 / 12    |
| attacker: hashes burned for admission | 53812      |
| receiver: blobs scanned               | 13         |
| receiver: bytes downloaded            | 6656       |
| receiver: scan time                   | 8.193118ms |
| receiver: real notifications found    | 1          |

## (b) addressed garbage

|                                    |             |
| ---------------------------------- | ----------- |
| attacker: garbage frames injected  | 6           |
| receiver: frames trial-decrypted   | 7           |
| receiver: drain time               | 46.233618ms |
| receiver: real proposals recovered | 1           |

## (c) valid-decoy probe

|                                          |                                                                  |
| ---------------------------------------- | ---------------------------------------------------------------- |
| attacker: probe cost (spent to receiver) | 0.30000000 BTC                                                   |
| receiver: on-chain revenue               | 0.30000000 BTC                                                   |
| receiver: revenue swept to wallet        | c70097102ec3a6a2a98bfdc0b520e6553cde6df4ada0e7637d0ad7ef13c86b97 |
| attacker: re-probes of the same coin     | 1                                                                |
| receiver: re-probes dropped by dedupe    | 1                                                                |

## (f) board-cap flood

|                                            |                                                                  |
| ------------------------------------------ | ---------------------------------------------------------------- |
| attacker: board posts to reach cap         | 7                                                                |
| attacker: hashes burned                    | 19902                                                            |
| attacker: regtest coin cost                | 0 (free on regtest)                                              |
| honest sender: board post status           | 503                                                              |
| honest sender: payment outcome             | completed as vanilla silent payment                              |
| receiver: payment recovered from its queue | 20650ed633595f7657e864a8840c06c1194ba15518b973a2d694bb1fcd292d63 |
| payments failed                            | 0                                                                |

## fallback notice

|                                   |     |
| --------------------------------- | --- |
| mailbox frames processed          | 3   |
| distinct candidate transactions   | 2   |
| payments detected                 | 1   |
| foreign notices rejected          | 1   |
| chain transactions scanned        | 0   |
| targeted chain lookups (gettxout) | 1   |
| blocks downloaded                 | 0   |

## lazy audit

|                              |       |
| ---------------------------- | ----- |
| index bytes                  | 440   |
| full-chain bytes, same range | 15657 |
| records scanned              | 4     |
| ECDH operations              | 4     |
| unclaimed payments found     | 1     |
| blocks fetched to claim      | 1     |
