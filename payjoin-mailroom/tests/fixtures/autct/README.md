# aut-ct test fixtures

Fixtures for `tests/zk_sidecar.rs`, which runs a real aut-ct verifier
when `AUTCT_EXE` names one.

`fakekeys-6.aks` is copied verbatim from
[AdamISZ/aut-ct](https://github.com/AdamISZ/aut-ct)
(`testdata/fakekeys-6.aks`, MIT licensed, Copyright (c) 2024 Adam
Gibson). It is a six-key set built from the raw private keys
`0x01..0x06` repeated to 32 bytes.

`member-key-2.enc` and `member-key-3.enc` are the signet WIF encodings
of raw keys `0x02` and `0x03`, encrypted with the password `PASS` by
`autct -M encryptkey`. Only these two of the six verify against the
set: the key set lifts every leaf to an even-y point, while the prover
takes the public key as it is, so a key whose public point has odd y
fails the membership check.
