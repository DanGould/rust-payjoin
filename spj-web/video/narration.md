# Silent Payjoin demo: narration

One block per segment. The `## id` line names the audio file (`vo/<id>.wav`); the text under it is
what is said. Edit the text freely. To re-voice, put new files with the same names in a directory and run
`build.sh OUT.mp4 narration.md <that-dir>`. The picture waits for each segment to finish, so a longer read is fine.
`tts.py` fixes how Kokoro says "payjoin" (the "join" of coinjoin) without any markup here.
The build also writes the subtitles (`silent-payjoin-demo.srt`, `.vtt`) from this text, timed to the take.

## intro

Bob wants silent payments and payjoin. Today, his wallet makes him toggle between them. Turn one on, and the other turns off.

## problem

Naively, the two don't work together. The onchain address derived from a silent payment address depends on the transaction's inputs. Bob's wallet redoes the derivation math to find his money. In payjoin, Bob adds a coin, and that derivation would point to some different address. His wallet wouldn't be able to see the money. And a payjoin mailbox is one-time, while a silent payment address is reused.

## overview

This video shows two ways to get both. A one-time URI, and a contact URI, for someone Bob transacts with again and again. There's not one open donation address and mailbox for everyone. More on that at the end.

## one-time

First, a one-time Silent Payjoin URI.

## uri

Bob asks for forty thousand sats. His URI carries an ordinary address, his silent payment address, and a payjoin mailbox.

## carol

Carol's wallet knows payjoin, but not silent payments. It pays the address, Bob adds a coin, and it's an ordinary payjoin.

## alice-scan

Alice's wallet speaks silent payments. She scans Bob's next URI.

## alice-send

Alice works out Bob's output from her coin and his silent payment address, signs, and drops it in his mailbox.

## bob-adds

Bob finds it by scanning, and adds a coin. That changes the inputs, so he works out his output again. And he attaches a short proof, so Alice can check his math before she signs.

## alice-checks

Alice checks the proof, and works out Bob's output herself. It matches, and it pays him at least fifty thousand sats. Then she signs.

## confirmed

Confirmed. And if Bob ever loses this phone, a fresh wallet from his backup words and derivation path runs the same scan, and finds the same money.

## contact-note

Alice saves Bob as a contact. The URI carries no name, so she types one. Her wallet notes there's no reusable payjoin yet. She can scan Bob's contact URI to get it.

## contact

Second, a Silent Payjoin contact URI, for someone Bob transacts with again and again, like his exchange. No address. One mailbox, and one label, for many transfers.

## exchange-contact

Bob shows his contact URI. The exchange saves it once.

## withdraw

Bob withdraws from his exchange. His wallet is open, so each withdrawal is a Silent Payjoin.

## withdraw-more

Three withdrawals. Three Silent Payjoins. All found by scanning.

## offline

Two things can go wrong. If someone steals Bob's mailbox key, they still can't redirect the money: the payer only signs for the output it worked out. And if Bob is offline, like now, a scheduled payout he didn't start doesn't wait. After a few seconds, the exchange sends him a plain silent payment.

## offline-wake

When Bob wakes up, his wallet reads the waiting message, sees the transaction already went out, and finds it on chain by scanning.

## recap

A one-time URI for a one-time transfer, and a contact URI for someone Bob transacts with again and again. A funder paying many grantees at once batches them. That's multiparty, a separate design we don't cover here. Why not one open mailbox, next to a donation address? Any stranger could start a payjoin and see one of Bob's coins every time, without ever paying, and keep a proof for a coin that stays unspent. And anyone could fill the mailbox. So a donation address stays a plain silent payment address.

## end

Silent payments and payjoin, from one URI. More at payjoin dot org slash S P.
