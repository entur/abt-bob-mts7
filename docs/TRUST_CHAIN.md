# Trust chain

How a card is verified, drawn as boxes in boxes. The chain has only two certificates: the root (the public key of the card issuer) and the card certificate on the chip. Each box sits inside the box whose key sealed its door, and a door only opens if its seal verifies with the public key found in the box you are leaving.

![The MTS7 trust chain: the root certificate, the card certificate on the chip and the live signature, as three nested boxes with doors 1 to 3](trust-chain.svg)

For a step-by-step version, which also shows an edited and a cloned card, open [trust-chain.html](trust-chain.html) in a browser.

## The boxes

| Box | In the specifications | In this library | Where it comes from |
| --- | --- | --- | --- |
| Root certificate | Issuer public key, a JWK in `mtbPublicKeys` of the Participant Metadata Set (MTS4) | `IssuerPublicKey`, looked up in `ParticipantPublicKeys` by `iid` and `kid` | Fetched ahead of time, never from the card |
| Card certificate | ID MTB (MTS1) in the Cardholder certificates data object, tag `7F21` (MTS7) | `MobileTicketBundle`, its `tpk` becomes the `IccPublicKey` | `GET NEXT DATA` |
| Live tap | Response to `INTERNAL AUTHENTICATE` | Verified by `IccPublicKey.verify(..)` | Signed by the card on every read |

## The doors

 1. **Into the root.** The public key of the issuer is already on the terminal (or server). A card cannot bring its own root.
 2. **Root OUT, card certificate IN: integrity.** The issuer signed the card certificate (ES256). `IccPublicKeyBuilder` verifies the issuer signature first and only then creates the public key of the card from `tpk`, so the key of the card is only trusted if the issuer signed it. Reported by `Mts7Card.isVerifiedTrustChain()`.
 3. **Card certificate OUT, live tap IN: authenticity.** The terminal sends a 32-byte challenge with `INTERNAL AUTHENTICATE` (this library uses random bytes, MTS7 suggests a SHA-256 hash of the time, the terminal ID and so on). The card signs it with its private key, which cannot be read out of the chip, and the signature is verified with the public key of the card. Reported by `Mts7Card.isVerifiedPrivateKeyPresent()`.

## What each factory catches

| Card | `VerifyMts7CardFactory` (doors 2 and 3) | `VerifyKeyPairMts7CardFactory` (door 3 only) |
| --- | --- | --- |
| Genuine | accepted | accepted |
| Edited certificate: the public key of the card swapped for one of the attacker's, on the attacker's chip | rejected at door 2 | **accepted**, as the chip of the attacker has the private key for the swapped `tpk` |
| Cloned card: an exact copy of the certificate, without the private key | rejected at door 3 | rejected |
| Card from an unknown issuer | rejected, there is no issuer public key | accepted |

The same goes for `VerifyTrustChainMts7ProcessorFactory` and `VerifyKeyPairMts7ProcessorFactory` in `reader`. A card which fails at door 2 is also reported with `UnableToVerifyKeyPairException`, because without a trusted key for the card the signature from door 3 cannot be verified either; `getResult().isVerifiedTrustChain()` tells the two apart.

## Not checked by this library

The specifications describe a few more checks, which are not done in `core`:

 * the signature constraint `bob_sc` of the issuer key (MTS4)
 * `exp` and `nbf` in the Issuer Signature Protected Header (MTS1)
 * revocation of the token identifier (MTS7, appendix A)

## Sources

 * [MTS7 Travel card application v1.1.0](https://bitbucket.org/samtrafiken/bob-mts-7-travel-card-application)
 * [MTS1 Mobile ticket format](https://bitbucket.org/samtrafiken/bob-mts-1-mobile-ticket-format)
 * [MTS4 Coordination and key management v1.3.1](https://bitbucket.org/samtrafiken/bob-mts-4-coordination-and-key-management)
