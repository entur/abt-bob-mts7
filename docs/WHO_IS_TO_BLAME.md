# Who is to blame

Every problem is the problem of one side, and is reported with one of three exceptions in `api`:

| Side | Exception | A service may report it as |
| --- | --- | --- |
| The card | `InvalidCardMts7Exception` | an invalid card (token) |
| The reader which read the card and sent the exchanges, such as a control client | `ReaderMts7Exception` | an invalid request |
| The verifier, which checks the card on the device or in the backend: its issuer keys, its security provider, its configuration | `VerifierMts7Exception` | an internal error |

The card is only blamed when it is at fault. Every command is checked to be as MTS7 specifies it before the response of the card to it, so a card which rejects a command which is not as specified is not to blame. The processors throw the problems of the card and of the reader as they are, and a problem with the verifier as the cause of an `ExecutionException`.

## The card is checked first

A card which is not valid is to blame for that, whatever else it did, so that it cannot shift the blame to the reader by making the reader fail where it can. The card is checked as far as it can be before a problem with the reader is reported:

 * The application-related data is read after door 2 and door 3, as it is not needed for them. If the rest of the select application response or the application-related data could not be retrieved, the readers read the card on, and `Mts7ApduPayloadsFactory` keeps the problem in the payloads (`getReaderProblem()`), so that the card factories report it only if the card passes both doors.
 * The same goes for an incomplete response to INTERNAL AUTHENTICATE, which only stops door 3: the card is still checked at door 2.
 * If `InFlightMts7CardFactory` cannot read the card completely, as it stops responding (`IOException`) or makes the reader fail (`ReaderMts7Exception`), but what was read of it shows that it is not valid, it throws that problem on the card side instead, with the other one suppressed.

## Every exception

The exceptions in the order in which they can first occur: reading the card, sorting out the exchanges, what the card returned, door 2 and door 3. For the same problems one command at a time, see [Command by command](#command-by-command).

| Exception | Description | Card | Reader | Verifier |
| --- | --- | :---: | :---: | :---: |
| `MalformedCardResponseException` | A response without a status word in the exchanges, which may not be as the card sent it. On the device, which reads the card as it is, a response shorter than a status word is the card's problem (`UnexpectedCardResponseException`) | | ✅ | |
| `UnableToSelectApplicationException` | The card does not respond with success to SELECT, while it is read on the device | ✅ | | |
| `MissingCardCommandsException` | Commands or responses are missing: fewer than three exchanges, no GET (NEXT) DATA of an MTB, a missing exchange, or a card which was not completely read before the processor was closed or within its lifetime | | ✅ | |
| `MalformedCardCommandException` | A command which is not as MTS7 specifies it: shorter than its header or otherwise malformed, GET (NEXT) DATA or GET RESPONSE without Le or with data, or INTERNAL AUTHENTICATE without Le or with a challenge which is not a SHA-256 hash of 32 bytes (MTS7 4.1.4). Also a command which the card rejects, as it need not support it: SELECT of a longer application identifier than `A0 00 00 07 81 01` (MTS7 4.1.1), or INTERNAL AUTHENTICATE with an Le for less than the 256 bytes of an RSA signature, unless the card asked for that Le | | ✅ | |
| `UnexpectedCardCommandException` | A command which MTS7 does not have at that point: not SELECT first, not INTERNAL AUTHENTICATE last (followed by GET RESPONSE if the card has more), something else than GET (NEXT) DATA or GET DATA of `6E` in between, GET RESPONSE after a complete response, or SELECT of another application than `A0 00 00 07 81 01` | | ✅ | |
| `UnexpectedCardResponseException` | The card does not respond with success to a command as MTS7 specifies it, such as `6A82` to SELECT (not an MTS7 card), `6A88` to the first GET NEXT DATA (no MTB, MTS7 3.1.5), `6700` (wrong length) to SELECT or INTERNAL AUTHENTICATE with the lengths of their examples in MTS7, `61xx` still after 256 GET RESPONSE commands, `6Cxx` or `6700` to the Le which the card asked for, or, on the device, a response shorter than a status word | ✅ | | |
| `InsufficientCardCommandsException` | The reader did not retrieve what the card has: the rest of a response after `61xx`, to any command (MTS7 2.1 and 4.1.3), a command which the card asked for again with other lengths (`6Cxx`, or `6700` to other lengths than in an example in MTS7 which every card must accept, also when the reader has no other lengths to send it with), or the application-related data (`6E`) with GET DATA, when the select application response has none, as it need not (MTS7 4.1.1). Reported only once the card has passed the doors which the missing response is not needed for | | ✅ | |
| `InvalidCardMts7Exception` | What the card returned is malformed: a select application response which is not well-formed BER-TLV, application-related data (`6E`) without a valid application identifier, a GET DATA response which is not a Mobile Ticket Bundle or has no Issuer Signature Protected Header, an `alg` which is missing or not `ES256` or `RS256` (MTS1 2.4), or an `iid` which is not a number | ✅ | | |
| `UnableToConstructIssuerKeyException` | Door 2: the issuer key is among the issuer keys, but cannot be created, is not supported, or is not accepted by the security provider | | | ✅ |
| `UnknownIssuerKeyInvalidCardMts7Exception` | Door 2: the issuer key is not among the issuer keys, and the `UnknownIssuerKeyPolicy` blames the card | ✅ | | |
| `OutdatedIssuerKeysException` | Door 2: the issuer key is not among the issuer keys, and the `UnknownIssuerKeyPolicy` blames the keys, which may be out of date | | | ✅ |
| `TrustChainInvalidCardMts7Exception` | Door 2: the issuer signature is not valid or malformed, or `alg` does not match the issuer key | ✅ | | |
| `NoSuchAlgorithmMts7Exception` | Door 2 or 3: the security provider does not have a key or signature algorithm | | | ✅ |
| `NonCompliantIccKeyInvalidCardMts7Exception` | Door 3: the public key of the card (`tpk`) is missing, not EC with P-256 or RSA with a modulus of 2048 bits (MTS7 2.1), or malformed | ✅ | | |
| `UnableToConstructIccKeyException` | Door 3: the public key of the card is as MTS7 specifies it, but the security provider does not accept it | | | ✅ |
| `UnableToConstructThumbprintKeyException` | Door 3: the thumbprint of the public key of the card cannot be created, although the key can | | | ✅ |
| `KeyPairInvalidCardMts7Exception` | Door 3: the signature of the card is not valid or malformed, as for a cloned card | ✅ | | |

## Not a problem of any side

* `TimeoutException` from `waitForVerify(..)` or `getMts7Card(..)`: the processing did not finish within the timeout, and goes on. A processor which is closed after the input has arrived still verifies the card.
 * `6700` (wrong length) to a command with other lengths than in an example in MTS7 which every card must accept, such as GET NEXT DATA with an extended Le, which the card need not support (MTS7 3.1.4), or `6Cxx` (wrong Le, ISO/IEC 7816-4 5.6): the reader sends the command again with other lengths. The card is only to blame for `6700` to SELECT with a short Le of `00` (MTS7 4.1.1) or without Le (appendix A), and to INTERNAL AUTHENTICATE with a short Le of `00` (MTS7 4.1.4). The examples of GET (NEXT) DATA and GET RESPONSE have an extended Le, and GET DATA of `6E` has none.
 * `61xx`, also without data and to any command: more of the response follows, which the reader retrieves with GET RESPONSE (MTS7 2.1).
 * No application-related data in the select application response: the readers retrieve it with GET DATA (`00 CA 00 6E`).
 * `6A88` to GET NEXT DATA after the first MTB: there are no more MTBs. The card is authenticated with the public key of its first MTB (MTS7 appendix A).
 * An Issuer Signed Ticket Bundle in another CBOR representation than the recommended one: it is verified as it is encoded (MTS1 2.3).

A bug, not to be reported as the problem of any side: a `RuntimeException`, such as a `NullPointerException` or an `IllegalArgumentException` for a missing or out of range argument, or an `IllegalStateException` from `waitForVerify(..)` of a processor which was never started.

## Unknown issuer keys

A card whose issuer key is not among the public keys may be forged, or genuine while the issuer keys are out of date, for example because the participant metadata could not be updated after the issuer started to use a new key. The card alone does not tell, so who is to blame is decided by an `UnknownIssuerKeyPolicy`, which is given to `VerifyMts7CardFactory`, `VerifyTrustChainMts7ProcessorFactory` or `UpdatableVerifyMts7CardFactorySupplier.newBuilder().withUnknownIssuerKeyPolicy(..)`:

 * `UnknownIssuerKeyPolicy.blameCard()` (the default): `UnknownIssuerKeyInvalidCardMts7Exception`.
 * `UnknownIssuerKeyPolicy.blameKeys()`: `OutdatedIssuerKeysException`, a problem with the verifier.
 * `UnknownIssuerKeyPolicy.blameCardIfConfirmedWithin(maximumAge, confirmedAt, clock)`: the card only if the keys were confirmed to be up to date (for example when the participant metadata was last downloaded or found unchanged) within the maximum age.
 * Your own, as the policy is a functional interface; policies can be combined with `and(..)`.

## Command by command

The same problems, one APDU command at a time: what can be wrong with the command, with the status word of the response, and with the data in it. A reader following MTS7 exchanges these commands with the card:

```
Reader                                         Card
SELECT A0 00 00 07 81 01                  →
                                          ←    64 (6E ..) 90 00, or just 90 00
GET DATA 6E                               →    only if there was no 6E above
                                          ←    6E .. 90 00
GET NEXT DATA 7F21                        →
                                          ←    the first MTB .. 61 xx
GET RESPONSE                              →    for as long as the card says 61 xx
                                          ←    .. 90 00
INTERNAL AUTHENTICATE <32-byte challenge> →
                                          ←    signature 90 00
```

The same checks are made in two places: on the device, while it reads the card (`Mts7ApduExchangesFactory`, `ProcessorMts7ApduExchangesFactory` and the processors), and in the backend, from the exchanges which the device sends (`Mts7ApduPayloadsFactory` and the card factories). A row which only applies to one of them says so.

### Responses which ask the reader for more

To any command, the card may answer with one of these, as ISO/IEC 7816-4 allows. None of them is a problem in itself, but the reader must act on it, or it is to blame (`InsufficientCardCommandsException`):

| Response | Meaning | The reader |
| --- | --- | --- |
| `61xx` | There is more of the response. Every card supports response chaining, for any command (MTS7 2.1), so the select application response and the signature may come in parts too | Retrieves the rest with GET RESPONSE, for as long as the card says `61xx` |
| `6Cxx` | Wrong Le, SW2 is the exact length (ISO/IEC 7816-4 5.6, which MTS7 4.3 says a terminal MUST accept) | Sends the same command again with Le `xx` |
| `67 00` to a command with other lengths than in an example which every card must accept | Wrong length, such as to an extended Le, which the card need not support (MTS7 3.1.4) | Sends the same command again with other lengths, such as a short Le of `00` |

The card is only to blame for `67 00` (`UnexpectedCardResponseException`) to a command with the lengths of an example in MTS7 which every card must accept: SELECT with a short Le of `00` (section 4.1.1) or without Le (appendix A), and INTERNAL AUTHENTICATE with a short Le of `00` (section 4.1.4). The examples of GET DATA, GET NEXT DATA and GET RESPONSE have an extended Le, and there is no example of GET DATA of `6E`, so `67 00` to these is never the card's problem. When the reader has no other lengths left to send such a command with, the reader is to blame (`InsufficientCardCommandsException`).

### The exchanges as a whole

| What goes wrong | Exception | Card | Reader | Verifier |
| --- | --- | :---: | :---: | :---: |
| No exchanges, fewer than three, or a missing exchange | `MissingCardCommandsException` | | ✅ | |
| The processor was closed before the card was read, or the card was not completely read within the lifetime of the processor (device) | `MissingCardCommandsException` | | ✅ | |
| A command between SELECT and INTERNAL AUTHENTICATE which is not GET (NEXT) DATA of `7F21`, GET DATA of `6E`, GET RESPONSE after `61xx`, the same command again after `6Cxx` or `67 00`, or a failed INTERNAL AUTHENTICATE (backend) | `UnexpectedCardCommandException` | | ✅ | |
| The card said `61xx`, and no GET RESPONSE followed (backend). For select application, the application-related data and INTERNAL AUTHENTICATE, reported only once the card has passed the doors which the response is not needed for | `InsufficientCardCommandsException` | | ✅ | |
| The card asked for the command again with other lengths, and it was not sent again, or there were no other lengths left to send it with | `InsufficientCardCommandsException` | | ✅ | |
| The card asked for the command again, although it was sent the Le which the card asked for (`6Cxx`) | `UnexpectedCardResponseException` | ✅ | | |
| A command shorter than its header (four bytes), or with length fields which do not add up | `MalformedCardCommandException` | | ✅ | |
| A response shorter than its status word (two bytes) in the exchanges, which may not be as the card sent it (backend) | `MalformedCardResponseException` | | ✅ | |
| A response shorter than its status word (two bytes), read from the card as it is (device) | `UnexpectedCardResponseException` | ✅ | | |

Not a problem of any side: a `TimeoutException` from `waitForVerify(..)` or `getMts7Card(..)`. The processing goes on, and can be waited for again.

### 1. SELECT

`00 A4 04 00 06 A0 00 00 07 81 01 00` (MTS7 4.1.1). The first command.

| What goes wrong | Exception | Card | Reader | Verifier |
| --- | --- | :---: | :---: | :---: |
| The first command is not SELECT by DF name (`00 A4 04 00`) (backend) | `UnexpectedCardCommandException` | | ✅ | |
| SELECT of another application than `A0 00 00 07 81 01` (backend) | `UnexpectedCardCommandException` | | ✅ | |
| SELECT of a longer application identifier which starts with `A0 00 00 07 81 01`, which the card rejects. Only the 6 bytes are submitted (MTS7 4.1.1), and the card need not have an application by a longer name (backend) | `MalformedCardCommandException` | | ✅ | |
| The card does not respond with success (`90 00`) to SELECT of `A0 00 00 07 81 01`, such as `6A 82` (not an MTS7 card), `62 85` (terminated), or `67 00` to the lengths of an example in MTS7 | `UnableToSelectApplicationException` (device), `UnexpectedCardResponseException` (backend) | ✅ | | |
| The response data is not well-formed BER-TLV, and there is no application-related data (`6E`) from GET DATA either | `InvalidCardMts7Exception` | ✅ | | |
| The response has application-related data (`6E`), but no application identifier (`4F`) of at least 16 bytes in it | `InvalidCardMts7Exception` | ✅ | | |

Not a problem of any side: an empty response, or one without application-related data. The File Management Data is only a SHOULD, and a terminal MUST accept an empty response (MTS7 4.1.1); the reader then retrieves `6E` with GET DATA. Padding (`00` or `FF`) before, between and after the data objects is allowed (ISO/IEC 7816-4 5.2.2), also inside `64` and `6E`; the reader and the library skip it in the same way, so that a card cannot make the reader look as if it did not retrieve the application-related data. A longer application identifier which the card accepts.

### 2. GET DATA of the application-related data

`00 CA 00 6E 00` (MTS7 4.1.1 and 4.1.2). Only when the select application response has no `6E`.

| What goes wrong | Exception | Card | Reader | Verifier |
| --- | --- | :---: | :---: | :---: |
| The select application response has no `6E`, and the reader did not send GET DATA of it, or could not retrieve it. Reported only once the card has passed door 2 and door 3 | `InsufficientCardCommandsException` | | ✅ | |
| The command has data, or no Le | `MalformedCardCommandException` | | ✅ | |
| The card does not respond with success, such as `6A 88` (no `6E`, which every card has) | `UnexpectedCardResponseException` | ✅ | | |
| The response has no application identifier (`4F`) of at least 16 bytes, or is malformed | `InvalidCardMts7Exception` | ✅ | | |

### 3. GET NEXT DATA of the Mobile Ticket Bundle

`00 CC 7F 21 00 00 00`, or GET DATA `00 CA 7F 21 ..` (MTS7 3.1.5 and 4.1.2). The card returns its first MTB, and this library only uses that one (MTS7 appendix A). It holds the card certificate, which is checked at door 2 (see [Trust chain](TRUST_CHAIN.md)).

The device sends GET NEXT DATA with an extended Le first, which saves GET RESPONSE round trips for a card which supports extended length.

| What goes wrong | Exception | Card | Reader | Verifier |
| --- | --- | :---: | :---: | :---: |
| There is no GET (NEXT) DATA of `7F21` | `MissingCardCommandsException` | | ✅ | |
| The command has data, or no Le | `MalformedCardCommandException` | | ✅ | |
| The card rejects both an extended and a short Le with `67 00` (device) | `InsufficientCardCommandsException` | | ✅ | |
| `6A 88` to the first GET NEXT DATA: no MTB, although the card MUST have one (MTS7 3.1.5) | `UnexpectedCardResponseException` | ✅ | | |
| Any other response which is not success | `UnexpectedCardResponseException` | ✅ | | |
| The response is not a Mobile Ticket Bundle, or has no Issuer Signature Protected Header | `InvalidCardMts7Exception` | ✅ | | |
| `alg` is missing, or not `ES256` or `RS256` (MTS1 2.4) | `InvalidCardMts7Exception` | ✅ | | |
| `iid` is not a number | `InvalidCardMts7Exception` | ✅ | | |
| Door 2: the issuer key (`iid` and `kid`) is among the issuer keys, but cannot be created, is not supported, or is not accepted by the security provider | `UnableToConstructIssuerKeyException` | | | ✅ |
| Door 2: the issuer key is not among the issuer keys, and the `UnknownIssuerKeyPolicy` blames the card | `UnknownIssuerKeyInvalidCardMts7Exception` | ✅ | | |
| Door 2: the issuer key is not among the issuer keys, and the `UnknownIssuerKeyPolicy` blames the keys, which may be out of date | `OutdatedIssuerKeysException` | | | ✅ |
| Door 2: `alg` does not match the issuer key, or the issuer signature is not valid or malformed | `TrustChainInvalidCardMts7Exception` | ✅ | | |
| Door 2: the security provider does not have the issuer signature algorithm | `NoSuchAlgorithmMts7Exception` | | | ✅ |
| The public key of the card (`tpk`) is missing, not EC with P-256 or RSA with a modulus of 2048 bits (MTS7 2.1), or malformed | `NonCompliantIccKeyInvalidCardMts7Exception` | ✅ | | |
| `tpk` is as MTS7 specifies it, but the security provider does not accept it | `UnableToConstructIccKeyException` | | | ✅ |
| The thumbprint of `tpk` cannot be created, although the key can | `UnableToConstructThumbprintKeyException` | | | ✅ |

With `trustUnknownRootKeys`, a card whose issuer key is not among the issuer keys skips door 2, and the policy is not asked.

Not a problem of any side:

 * `6A 88` to a GET NEXT DATA after the first MTB: there are no more MTBs (MTS7 4.1.2).
 * An Issuer Signed Ticket Bundle in another CBOR representation than the recommended one: it is verified as it is encoded (MTS1 2.3).

### 4. GET RESPONSE

`00 C0 00 00 00 00 00`, or `00 C0 00 00 00` with a short Le (MTS7 2.1 and 4.1.3). After `61xx` to any command, for as long as the card has more.

| What goes wrong | Exception | Card | Reader | Verifier |
| --- | --- | :---: | :---: | :---: |
| GET RESPONSE after a complete response (backend) | `UnexpectedCardCommandException` | | ✅ | |
| The command has data, or no Le | `MalformedCardCommandException` | | ✅ | |
| The card does not respond with success or `61xx` | `UnexpectedCardResponseException` | ✅ | | |
| The card still says `61xx` after 256 GET RESPONSE commands | `UnexpectedCardResponseException` | ✅ | | |

### 5. INTERNAL AUTHENTICATE

`00 88 00 00 20 <32-byte challenge> 00` (MTS7 4.1.4). The last command, possibly followed by GET RESPONSE. The card signs the challenge with its private key, and the signature is checked with `tpk` at door 3.

| What goes wrong | Exception | Card | Reader | Verifier |
| --- | --- | :---: | :---: | :---: |
| The last command is not INTERNAL AUTHENTICATE `00 88 00 00` (backend) | `UnexpectedCardCommandException` | | ✅ | |
| The challenge is not a SHA-256 hash of 32 bytes (MTS7 4.1.4) | `MalformedCardCommandException` | | ✅ | |
| The command has no Le, so it does not ask for the signature | `MalformedCardCommandException` | | ✅ | |
| The card rejects a command with an Le for less than 256 bytes, the length of an RSA signature, which the card may not be able to return within it, unless the card asked for that Le (`6Cxx`) (backend) | `MalformedCardCommandException` | | ✅ | |
| The card does not respond with success to the last INTERNAL AUTHENTICATE, with an Le of `00` (or extended), or the Le which it asked for | `UnexpectedCardResponseException` | ✅ | | |
| Door 3: the security provider does not have the key or signature algorithm of the card | `NoSuchAlgorithmMts7Exception` | | | ✅ |
| Door 3: the signature is not valid or malformed, as for a cloned card | `KeyPairInvalidCardMts7Exception` | ✅ | | |

Not a problem of any side: an INTERNAL AUTHENTICATE which failed before the last one. It is skipped.

## Sources

 * [MTS7 Travel card application v1.1.0](https://bitbucket.org/samtrafiken/bob-mts-7-travel-card-application)
 * [MTS1 Mobile ticket format](https://bitbucket.org/samtrafiken/bob-mts-1-mobile-ticket-format)
 * ISO/IEC 7816-4:2013, sections 5.1 (lengths), 5.2.2 (padding) and 5.6 (status words)
