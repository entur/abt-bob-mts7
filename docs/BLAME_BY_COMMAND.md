# Who is to blame, command by command

Every problem with a card read is blamed on one of three sides: the card (`InvalidCardMts7Exception`), the reader which read the card and sent the exchanges (`ReaderMts7Exception`), or the verifier, which checks the card on the device or in the backend: its issuer keys, its security provider and its configuration (`VerifierMts7Exception`). The [README](../README.md#who-is-to-blame) lists the exceptions in the order in which they occur. This page goes through the same problems one APDU command at a time: what can be wrong with the command, with the status word of the response, and with the data in it.

A reader following MTS7 exchanges these commands with the card:

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

Each command is checked before the response of the card to it. A card which rejects a command that is not as MTS7 specifies it is not to blame.

A card which is not valid is to blame for that, whatever else it did. The card is checked at door 2 and door 3 before a problem with the reader is reported which does not stop them: an incomplete select application response, missing application-related data, and, for door 2, an incomplete response to INTERNAL AUTHENTICATE. The readers on the device read the card on after such a problem, and `Mts7ApduPayloadsFactory` keeps it in the payloads (`getReaderProblem()`) for the card factories to report once the card has passed. A card which stops responding, or makes the reader fail, after its MTB is to blame if its MTB is not valid (`InFlightMts7CardFactory`).

## Responses which ask the reader for more

To any command, the card may answer with one of these, as ISO/IEC 7816-4 allows. None of them is a problem in itself, but the reader must act on it, or it is to blame (`InsufficientCardCommandsException`):

| Response | Meaning | The reader |
| --- | --- | --- |
| `61xx` | There is more of the response. Every card supports response chaining, for any command (MTS7 2.1), so the select application response and the signature may come in parts too | Retrieves the rest with GET RESPONSE, for as long as the card says `61xx` |
| `6Cxx` | Wrong Le, SW2 is the exact length (ISO/IEC 7816-4 5.6, which MTS7 4.3 says a terminal MUST accept) | Sends the same command again with Le `xx` |
| `67 00` to a command with other lengths than in an example which every card must accept | Wrong length, such as to an extended Le, which the card need not support (MTS7 3.1.4) | Sends the same command again with other lengths, such as a short Le of `00` |

The card is only to blame for `67 00` (`UnexpectedCardResponseException`) to a command with the lengths of an example in MTS7 which every card must accept: SELECT with a short Le of `00` (section 4.1.1) or without Le (appendix A), and INTERNAL AUTHENTICATE with a short Le of `00` (section 4.1.4). The examples of GET DATA, GET NEXT DATA and GET RESPONSE have an extended Le, and there is no example of GET DATA of `6E`, so `67 00` to these is never the card's problem. When the reader has no other lengths left to send such a command with, the reader is to blame (`InsufficientCardCommandsException`).

## The exchanges as a whole

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

## 1. SELECT

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

## 2. GET DATA of the application-related data

`00 CA 00 6E 00` (MTS7 4.1.1 and 4.1.2). Only when the select application response has no `6E`.

| What goes wrong | Exception | Card | Reader | Verifier |
| --- | --- | :---: | :---: | :---: |
| The select application response has no `6E`, and the reader did not send GET DATA of it, or could not retrieve it. Reported only once the card has passed door 2 and door 3 | `InsufficientCardCommandsException` | | ✅ | |
| The command has data, or no Le | `MalformedCardCommandException` | | ✅ | |
| The card does not respond with success, such as `6A 88` (no `6E`, which every card has) | `UnexpectedCardResponseException` | ✅ | | |
| The response has no application identifier (`4F`) of at least 16 bytes, or is malformed | `InvalidCardMts7Exception` | ✅ | | |

## 3. GET NEXT DATA of the Mobile Ticket Bundle

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

## 4. GET RESPONSE

`00 C0 00 00 00 00 00`, or `00 C0 00 00 00` with a short Le (MTS7 2.1 and 4.1.3). After `61xx` to any command, for as long as the card has more.

| What goes wrong | Exception | Card | Reader | Verifier |
| --- | --- | :---: | :---: | :---: |
| GET RESPONSE after a complete response (backend) | `UnexpectedCardCommandException` | | ✅ | |
| The command has data, or no Le | `MalformedCardCommandException` | | ✅ | |
| The card does not respond with success or `61xx` | `UnexpectedCardResponseException` | ✅ | | |
| The card still says `61xx` after 256 GET RESPONSE commands | `UnexpectedCardResponseException` | ✅ | | |

## 5. INTERNAL AUTHENTICATE

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
