# Trust chain

How a card is verified, drawn as boxes in boxes. The chain has only two certificates: the root (the public key of the card issuer) and the card certificate on the chip. Each box sits inside the box whose key sealed its door, and a door only opens if its seal verifies with the public key found in the box you are leaving.

![The MTS7 trust chain: the root certificate, the card certificate on the chip and the live signature, as three nested boxes with doors 1 to 3](trust-chain.svg)

For a step-by-step version, which also shows an edited and a cloned card, see the [interactive trust chain](https://entur.github.io/abt-bob-mts7/trust-chain.html) (served by GitHub Pages from [trust-chain.html](trust-chain.html)).

## The boxes

| Box | In the specifications | In this library | Where it comes from |
| --- | --- | --- | --- |
| Root certificate | Issuer public key, a JWK in `mtbPublicKeys` of the Participant Metadata Set (MTS4) | `IssuerPublicKey`, looked up in `ParticipantPublicKeys` by `iid` and `kid` | Fetched ahead of time, never from the card |
| Card certificate | ID MTB (MTS1) in the Cardholder certificates data object, tag `7F21` (MTS7) | `MobileTicketBundle`, its `tpk` becomes the `IccPublicKey` | `GET NEXT DATA` |
| Live tap | Response to `INTERNAL AUTHENTICATE` | Verified by `IccPublicKey.verify(..)` | Signed by the card on every read |

## The doors

 1. **Into the root.** The public key of the issuer is already on the terminal (or server). A card cannot bring its own root.
 2. **Root OUT, card certificate IN: integrity.** The issuer signed the card certificate, with the algorithm named by `alg` in the header: ES256, or the fallback RS256 (MTS1, section 2.4). `alg` is only about the issuer signature. A card whose `alg` is missing or not one of these two is malformed, and rejected by all factories and processors before the issuer key is looked up; one whose `alg` does not match the issuer key is rejected here, before the signature is verified. The algorithm of the card itself follows from the type of its public key `tpk` (EC with P-256, or RSA). `IccPublicKeyBuilder` verifies the issuer signature first and only then creates the public key of the card from `tpk`, so the key of the card is only trusted if the issuer signed it. Reported by `Mts7Card.isVerifiedTrustChain()`.
 3. **Card certificate OUT, live tap IN: authenticity.** The terminal sends a 32-byte challenge with `INTERNAL AUTHENTICATE` (this library uses random bytes, MTS7 suggests a SHA-256 hash of the time, the terminal ID and so on). The card signs it with its private key, which cannot be read out of the chip, and the signature is verified with the public key of the card. Reported by `Mts7Card.isVerifiedPrivateKeyPresent()`.

## What each factory catches

| Card | `VerifyMts7CardFactory` (doors 2 and 3) | `VerifyKeyPairMts7CardFactory` (door 3 only) |
| --- | --- | --- |
| Genuine | accepted | accepted |
| Edited certificate: the public key of the card swapped for one of the attacker's, on the attacker's chip | rejected at door 2 | **accepted**, as the chip of the attacker has the private key for the swapped `tpk` |
| Cloned card: an exact copy of the certificate, without the private key | rejected at door 3 | rejected |
| Card from an unknown issuer | rejected, there is no issuer public key (accepted at door 3 alone with `trustUnknownRootKeys`) | accepted |

`VerifyMts7CardFactory` and `VerifyTrustChainMts7ProcessorFactory` can be created with `trustUnknownRootKeys`, for when the issuer public keys are known to be incomplete. A card whose root key (by `iid` and `kid`) is not among the issuer public keys is then checked at door 3 only, like `VerifyKeyPairMts7CardFactory` does, and accepted with `isVerifiedTrustChain()` false. A card whose root key is known must still pass both doors, so an edited certificate of a known issuer is still rejected, but an attacker can claim an issuer or `kid` which is not in the set: such a card has the same strength as with `VerifyKeyPairMts7CardFactory`.

The same goes for `VerifyTrustChainMts7ProcessorFactory` and `VerifyKeyPairMts7ProcessorFactory` in `reader`. A card which fails at door 2 is rejected with `TrustChainInvalidCardMts7Exception` (the issuer signature is not valid, or, as the subclass `UnknownIssuerKeyInvalidCardMts7Exception`, the issuer key is unknown), and one which fails at door 3 with `KeyPairInvalidCardMts7Exception`. Both are subclasses of `InvalidCardMts7Exception`, which is only for problems on the card side. If the issuer key is known but we cannot use it (its type is not supported, or the security provider does not accept it), that is a problem on our side, not the card's: `UnableToConstructIssuerKeyException`, an `InfrastructureMts7Exception`.

## Not checked by this library

The specifications describe a few more checks, which are not done in `core`:

 * the signature constraint `bob_sc` of the issuer key (MTS4)
 * `exp` and `nbf` in the Issuer Signature Protected Header (MTS1)
 * revocation of the token identifier (MTS7, appendix A)

## Sources

 * [MTS7 Travel card application v1.1.0](https://bitbucket.org/samtrafiken/bob-mts-7-travel-card-application)
 * [MTS1 Mobile ticket format](https://bitbucket.org/samtrafiken/bob-mts-1-mobile-ticket-format)
 * [MTS4 Coordination and key management v1.3.1](https://bitbucket.org/samtrafiken/bob-mts-4-coordination-and-key-management)
