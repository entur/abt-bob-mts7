[![Maven Central](https://img.shields.io/maven-central/v/no.entur.abt.bob.mts7/mts7-parent.svg)](https://mvnrepository.com/artifact/no.entur.abt.bob.mts7/mts7-parent)

# abt-bob-mts7
This project hosts a set of modules for [MTS7](https://samtrafiken.atlassian.net/wiki/spaces/BOB/pages/5192286235/MTS+7+Travel+Card+Application) NFC tag reader support. Supports two client modes:

 * Thin client
   * issues commands and collects resulting response APDUs
   * relies on the backend to do the heavy lifting (i.e. parsing etc)
 * Regular client
   * issues commands and collects resulting response APDUs
   * attempts to make the server do the heavy lifiting
   * falls back to parsing locally
     * verify the card has private key
     * verify keychain

# License
[European Union Public Licence v1.2](https://eupl.eu/).

## Implementation guide

> **The guides are for clients only**, i.e. the code which talks to the card (for example a mobile app or a terminal). They do not cover the server which receives the commands and responses. Parsing and verifying those on a server is done with `core`.

Select between three approaches:

 * [online only](#online-only)
 * [online with offline fallback](#online-with-offline-fallback)
 * [offline](#offline)

### Before you start

 * Add the artifact which you need (group id `no.entur.abt.bob.mts7`, use the latest release):
   * `simple-reader` for online only. It only depends on `api` and `simple-api`, so there is no parsing or crypto in the client.
   * `reader` for online with offline fallback and for offline. It brings `core` and `simple-reader`.
 * Implement your own class of type `Mts7Exchange` for talking to the card (`getTagId()` and `transceive(byte[])`). The library sends the commands and checks the status codes of the responses.
 * Create the factories **once** and share them between card readers and threads, see [Threads and performance](#threads-and-performance).

<details>
  <summary>Dependencies (Maven and Gradle)</summary>

```xml
<dependency>
    <groupId>no.entur.abt.bob.mts7</groupId>
    <artifactId>reader</artifactId>
    <version>VERSION</version>
</dependency>
```

```groovy
implementation "no.entur.abt.bob.mts7:reader:VERSION"
```
</details>

<details>
  <summary>Mts7Exchange for Android (IsoDep)</summary>

```java
import java.io.IOException;

import android.nfc.tech.IsoDep;

import no.entur.abt.bob.mts7.simple.reader.Mts7Exchange;

public class IsoDepMts7Exchange implements Mts7Exchange {

    private final IsoDep isoDep;

    public IsoDepMts7Exchange(IsoDep isoDep) {
        this.isoDep = isoDep;
    }

    @Override
    public byte[] getTagId() {
        return isoDep.getTag().getId();
    }

    @Override
    public byte[] transceive(byte[] command) throws IOException {
        return isoDep.transceive(command);
    }
}
```

Use it while the card is connected:

```java
IsoDep isoDep = IsoDep.get(tag);
isoDep.connect();
try {
    Mts7Exchange exchange = new IsoDepMts7Exchange(isoDep);

    // ... read the card using the exchange, see below
} finally {
    isoDep.close();
}
```

For a PC reader using `javax.smartcardio`, see the [example](examples/mts7-reader-example).
</details>

### Online only
Overview:
 
 * issue three (logical) commands and store command/responses as raw APDUs
   * the response to any command may be split due to max transceive length (so checking the response status code is necessary: `61xx` means that there is more data, which is fetched with GET RESPONSE, MTS7 2.1)
 * post to backend as a command/response train
   * split commands can be submitted together or in (original) parts; the library keeps the original parts

In other words, no parsing or crypto operations are necessary in client.

Implementation using 'thin' client:

 * add `simple-reader` artifact
 * Implement your own class of type `Mts7Exchange` for talking to the card
 * Create an instance of `Mts7ApduExchangesFactory`
 * Create `Mts7ApduExchanges` from `Mts7ApduExchangesFactory.createCard(..)`. Pass the response to *select application* if your platform has already selected the application, or null to have the library do it.
 * Post the exchanges (`getTagId()` and `getExchanges()`) to the backend.

`createCard(..)` throws `IOException` if the card cannot be reached (for example if it is moved away from the reader) and an `InvalidCardMts7Exception` if the card answers something unexpected (`UnableToSelectApplicationException` if the application cannot be selected, `UnexpectedCardResponseException` for other status words).

<details>
  <summary>Code example (backend stands for your own code)</summary>

```java
// once: shared by all card readers and threads
Mts7ApduExchangesFactory factory = new Mts7ApduExchangesFactory();

// for each card, where 'exchange' is the Mts7Exchange for the card
// (null: the library selects the application; pass the response if your platform has already done so)
Mts7ApduExchanges exchanges = factory.createCard(exchange, null);

// the command and response of each exchange, in order: select application, get next data
// (followed by get response for as long as the card has more data), internal authenticate
backend.post(exchanges.getTagId(), exchanges.getExchanges());
```
</details>

### Online with offline fallback

Overview:
 
 * (optional) retrieve the participant metadata, which has the public keys of the issuers, from the backend. It is needed to verify the trust chain locally.
 * issue three (logical) commands and store command/responses as raw APDUs
   * some commands are split due to max transceive length
   * the card is also processed in the background while it is read, so the result is (almost) ready when the card has been read
 * post to backend as a command/response train
   * split commands can be submitted together or in (original) parts
 * if server call fails, use the card details which were worked out locally (decoded, and the card verified)
   * without talking to the card again 

Implementation:

 * add `reader` artifact
 * Implement your own class of type `Mts7Exchange` for talking to the card
 * Create a `Mts7ProcessorFactory`, which needs an `Executor` for its processors (yours: the library creates no threads, and you shut it down when the application stops):
   * Most secure: `VerifyTrustChainMts7ProcessorFactory` (requires the public keys of the issuers via `ParticipantPublicKeys`, which you build from the participant metadata, see [signed participant metadata](#signed-participant-metadata); with `trustUnknownRootKeys`, a card whose issuer key is not among them is only checked for the private key, see [TRUST_CHAIN.md](docs/TRUST_CHAIN.md)) or
   * Less secure: `VerifyKeyPairMts7ProcessorFactory` (only checks that the card has the private key, not who issued it)
 * Create `InFlightMts7CardFactory` 
 * Create `InFlightMts7Card` from `InFlightMts7CardFactory.create(..)` which contains the `Mts7ApduExchanges`. It is `Closeable`: close it when done (try-with-resources), or the processor keeps waiting for the card (for at most a minute).
 * Post the exchanges to the backend. If this fails, then
 * Call on `InFlightMts7Card.getMts7Card(timeout)` (in milliseconds; zero waits until the processing has finished) to obtain a `Mts7Card`
 * Process card details (thumbprint, serial etc) locally

`getMts7Card(..)` tells whose problem it is when a card is not verified: the card's, the reader's or the infrastructure's (see [Who is to blame](#who-is-to-blame) for every problem).

 * `InvalidCardMts7Exception` if the card cannot be trusted (a problem on the card side). For the details of such a card, use `LenientMts7CardFactory` (see below).
   * `TrustChainInvalidCardMts7Exception` (trust chain only) if the card certificate was not signed by a known issuer: the issuer signature is not valid or malformed, its algorithm (`alg` in the header) does not match the issuer key, or the issuer key is not among the public keys (unless the factory was created with `trustUnknownRootKeys`).
     * `UnknownIssuerKeyInvalidCardMts7Exception` (a subclass) if the issuer key is not among the public keys, with `getIssuerId()` and `getKeyId()`, and the `UnknownIssuerKeyPolicy` blames the card (see below).
   * `KeyPairInvalidCardMts7Exception` if the card did not prove that it has the private key, as for a cloned card, or its signature is malformed.
   * `NonCompliantIccKeyInvalidCardMts7Exception` if the public key of the card (`tpk` in its certificate) is not as MTS7 specifies it: missing, of a type which is not in MTS7 (EC with P-256, or RSA with a modulus of 2048 bits), or malformed.
   * `InvalidCardMts7Exception` itself if what the card returned is malformed: an issuer signature algorithm `alg` which is missing or not `ES256` or `RS256` (checked by all factories and processors before the issuer key is looked up), or application-related data (6E) without a valid application identifier, which has the serial and the participant identifier.
 * `ReaderMts7Exception` if the card was not completely read, as the processor was closed or the card was not read in time (`MissingCardCommandsException`), or the input was not as a reader following MTS7 provides it: no application-related data, neither in the select application response nor from GET DATA (`InsufficientCardCommandsException`), or a challenge for internal authenticate which is not a SHA-256 hash of 32 bytes (`MalformedCardCommandException`).
 * `TimeoutException` if the processing did not finish within the timeout. Nobody is to blame; the processing goes on, so it can be waited for again. After `close()`, a processing which has begun is still waited for: it stops waiting for more input, but goes on with the input which has arrived.
 * `ExecutionException` if the processing failed because of a problem with the infrastructure, which is the cause: an `InfrastructureMts7Exception`, namely
   * `UnableToConstructIssuerKeyException` if the issuer key of the card is among the public keys but cannot be created, is of a type which is not supported, or is not accepted by the security provider,
   * `UnableToConstructIccKeyException` if the public key of the card is as MTS7 specifies it, but not accepted by the security provider,
   * `NoSuchAlgorithmMts7Exception` if the security provider does not have a key or signature algorithm (the cause is the `NoSuchAlgorithmException`),
   * `UnableToConstructThumbprintKeyException` if the thumbprint of the card's public key cannot be created although the key can, or
   * `OutdatedIssuerKeysException` if the issuer key is not among the public keys, and the `UnknownIssuerKeyPolicy` blames the keys, which may be out of date;

   or a `RejectedExecutionException` if the executor did not run the processor. Anything else, such as a `RuntimeException`, is a bug.

<details>
  <summary>Code example (backend, participantMetadataJson and useLocally are your own code)</summary>

```java
// once, when the application starts: the public keys of the issuers, from the backend
List<ParticipantMetadata> participants = Arrays.asList(new ObjectMapper().readValue(participantMetadataJson, ParticipantMetadata[].class));
ParticipantPublicKeys keys = ParticipantPublicKeys.newBuilder().withParticipants(participants).build();

ExecutorService executor = Executors.newCachedThreadPool(); // yours: shut it down when the application stops
Mts7ProcessorFactory processorFactory = new VerifyTrustChainMts7ProcessorFactory(keys, executor);
InFlightMts7CardFactory factory = new InFlightMts7CardFactory(processorFactory);

// for each card, where 'exchange' is the Mts7Exchange for the card:
// reading the card also feeds the processor, which works on the card details in the background
try (InFlightMts7Card inFlight = factory.create(exchange, null)) {
    Mts7ApduExchanges exchanges = inFlight.getMts7ApduExchanges();
    try {
        backend.post(exchanges.getTagId(), exchanges.getExchanges());
    } catch (IOException e) {
        // the server could not be reached: use what was worked out while the card was read
        try {
            Mts7Card card = inFlight.getMts7Card(1000); // wait for at most a second

            useLocally(card);
        } catch (InvalidCardMts7Exception e2) {
            // a problem on the card side: reject the card
        } catch (ReaderMts7Exception e2) {
            // the card was not completely read: try again
        } catch (TimeoutException e2) {
            // not processed in time: try again, or wait longer
        } catch (ExecutionException e2) {
            // a problem with the infrastructure, see e2.getCause()
        }
    }
}
```
</details>

### Signed participant metadata

The participant metadata is published as a JWS (general JSON serialization), signed by the publisher of the metadata. Verify it before you use its keys, as whoever controls the participant metadata decides which cards are trusted:

 * `VerifiedParticipantMetadataFactory` parses the JWS, verifies its signatures and only then parses the payload (`ParticipantMetadataJwsParser` and `ParticipantMetadataJwsVerifier` do the parts).
 * The trusted keys are a JWK set which you have got from the publisher in advance; a signature is matched to a key by `kid`. One valid signature by a trusted key is enough, so a primary and a fallback signature can be combined; `getVerifiedHeaders()` tells which ones were verified.
 * The validity period of a signature (`notvalidbefore` and `notvalidafter` in its header) is checked against the current time, or a time of your own. Each of the two checks can be turned off in the constructor of the verifier, and a signature which does not have them is not limited in time.
 * `UnableToVerifyParticipantMetadataException` is thrown if the JWS or its payload cannot be parsed, or if no signature could be verified.

<details>
  <summary>Code example (trustedKeysJson and participantMetadataJws are your own)</summary>

```java
// the keys of the publisher of the participant metadata, which you trust
JWKSet trustedKeys = JWKSet.parse(trustedKeysJson);

VerifiedParticipantMetadataFactory metadataFactory = new VerifiedParticipantMetadataFactory(new ParticipantMetadataJwsParser(),
        new ParticipantMetadataJwsVerifier(trustedKeys));

// throws UnableToVerifyParticipantMetadataException if the participant metadata cannot be trusted
VerifiedParticipantMetadata verified = metadataFactory.create(participantMetadataJws);

ParticipantPublicKeys keys = ParticipantPublicKeys.newBuilder().withParticipants(verified.getParticipantMetadata()).build();
```
</details>

To store the participant metadata, keep the JWS and verify it again when it is loaded, or keep the payload of a verified JWS (`getJws().getPayload().toBytes()`) and parse it with `ParticipantMetadataJwsParser.parseParticipantMetadata(byte[])`, which does not verify anything.

### Offline

 * Like above, just don't post anything to the server.
 * Or read the card first and process it afterwards: `Mts7ApduPayloadsFactory` sorts out the responses of the exchanges, and `VerifyMts7CardFactory` verifies the card (`VerifyKeyPairMts7CardFactory` if there are no public keys; with `trustUnknownRootKeys`, a card whose issuer key is not among the public keys is verified like that, see [TRUST_CHAIN.md](docs/TRUST_CHAIN.md)). For the details of a card which cannot be verified, `LenientMts7ApduPayloadsFactory` and `LenientMts7CardFactory` extract as much as they can, also from a partial read, instead of rejecting it; nothing which they return can be trusted.

<details>
  <summary>Code example</summary>

```java
// once: shared by all card readers and threads ('keys' are the ParticipantPublicKeys, see above)
Mts7ApduExchangesFactory exchangesFactory = new Mts7ApduExchangesFactory();
Mts7ApduPayloadsFactory payloadsFactory = new Mts7ApduPayloadsFactory();
VerifyMts7CardFactory cardFactory = new VerifyMts7CardFactory(keys);

// for each card, where 'exchange' is the Mts7Exchange for the card
Mts7ApduExchanges exchanges = exchangesFactory.createCard(exchange, null);

try {
    Mts7ApduPayloads payloads = payloadsFactory.createCard(exchanges);
    Mts7Card card = cardFactory.create(payloads);
} catch (UnknownIssuerKeyInvalidCardMts7Exception e) {
    // the card refers to an issuer key which is not among the keys: a forged card, or the participant metadata is out of date;
    // log e.getIssuerId() and e.getKeyId() separately
} catch (InvalidCardMts7Exception e) {
    // a problem on the card side: it does not have the private key, was not issued by one of the issuers of the keys, or returned something malformed
} catch (ReaderMts7Exception e) {
    // a problem with the reader: the exchanges are not as a reader following MTS7 sends them
} catch (InfrastructureMts7Exception e) {
    // a problem with the infrastructure: an issuer key which cannot be created, a security provider without a signature algorithm, or a thumbprint which cannot be created
}
```
</details>

The card factories (`create(..)`) and the processors tell the sides apart in the same way, see [Who is to blame](#who-is-to-blame). The factories throw a problem with the infrastructure as it is, on the calling thread. Their constructors still throw `NoSuchAlgorithmException`, as the digest algorithm is checked when they are created. A verified card always has a thumbprint.

## Who is to blame

Every problem is the problem of one side, and is reported with one of three exceptions in `api`:

| Side | Exception | A service may report it as |
| --- | --- | --- |
| The card | `InvalidCardMts7Exception` | an invalid card (token) |
| The reader which read the card and sent the exchanges, such as a control client | `ReaderMts7Exception` | an invalid request |
| The infrastructure: the issuer keys, the security provider, the configuration | `InfrastructureMts7Exception` | an internal error |

The card is only blamed when it is at fault. Every command is checked to be as MTS7 specifies it before the response of the card to it, so a card which rejects a command which is not as specified is not to blame. The processors throw the problems of the card and of the reader as they are, and a problem with the infrastructure as the cause of an `ExecutionException`.

A card which is not valid is to blame for that, whatever else it did, so that it cannot shift the blame to the reader by making the reader fail where it can. The card is checked as far as it can be before a problem with the reader is reported:

 * The application-related data is read after door 2 and door 3, as it is not needed for them. If the rest of the select application response or the application-related data could not be retrieved, the readers read the card on, and `Mts7ApduPayloadsFactory` keeps the problem in the payloads (`getReaderProblem()`), so that the card factories report it only if the card passes both doors.
 * The same goes for an incomplete response to INTERNAL AUTHENTICATE, which only stops door 3: the card is still checked at door 2.
 * If `InFlightMts7CardFactory` cannot read the card completely, as it stops responding (`IOException`) or makes the reader fail (`ReaderMts7Exception`), but what was read of it shows that it is not valid, it throws that problem on the card side instead, with the other one suppressed.

The exceptions in the order in which they can first occur: reading the card, sorting out the exchanges, what the card returned, door 2 and door 3. For the same problems one command at a time, see [Who is to blame, command by command](docs/BLAME_BY_COMMAND.md).

| Exception | Description | Card | Reader | Infrastructure |
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

Not a problem of any side:

 * `TimeoutException` from `waitForVerify(..)` or `getMts7Card(..)`: the processing did not finish within the timeout, and goes on. A processor which is closed after the input has arrived still verifies the card.
 * `6700` (wrong length) to a command with other lengths than in an example in MTS7 which every card must accept, such as GET NEXT DATA with an extended Le, which the card need not support (MTS7 3.1.4), or `6Cxx` (wrong Le, ISO/IEC 7816-4 5.6): the reader sends the command again with other lengths. The card is only to blame for `6700` to SELECT with a short Le of `00` (MTS7 4.1.1) or without Le (appendix A), and to INTERNAL AUTHENTICATE with a short Le of `00` (MTS7 4.1.4). The examples of GET (NEXT) DATA and GET RESPONSE have an extended Le, and GET DATA of `6E` has none.
 * `61xx`, also without data and to any command: more of the response follows, which the reader retrieves with GET RESPONSE (MTS7 2.1).
 * No application-related data in the select application response: the readers retrieve it with GET DATA (`00 CA 00 6E`).
 * `6A88` to GET NEXT DATA after the first MTB: there are no more MTBs. The card is authenticated with the public key of its first MTB (MTS7 appendix A).
 * An Issuer Signed Ticket Bundle in another CBOR representation than the recommended one: it is verified as it is encoded (MTS1 2.3).

A bug, not to be reported as the problem of any side: a `RuntimeException`, such as a `NullPointerException` or an `IllegalArgumentException` for a missing or out of range argument, or an `IllegalStateException` from `waitForVerify(..)` of a processor which was never started.

### Unknown issuer keys

A card whose issuer key is not among the public keys may be forged, or genuine while the issuer keys are out of date, for example because the participant metadata could not be updated after the issuer started to use a new key. The card alone does not tell, so who is to blame is decided by an `UnknownIssuerKeyPolicy`, which is given to `VerifyMts7CardFactory`, `VerifyTrustChainMts7ProcessorFactory` or `UpdatableVerifyMts7CardFactorySupplier.newBuilder().withUnknownIssuerKeyPolicy(..)`:

 * `UnknownIssuerKeyPolicy.blameCard()` (the default): `UnknownIssuerKeyInvalidCardMts7Exception`.
 * `UnknownIssuerKeyPolicy.blameKeys()`: `OutdatedIssuerKeysException`, a problem with the infrastructure.
 * `UnknownIssuerKeyPolicy.blameCardIfConfirmedWithin(maximumAge, confirmedAt, clock)`: the card only if the keys were confirmed to be up to date (for example when the participant metadata was last downloaded or found unchanged) within the maximum age.
 * Your own, as the policy is a functional interface; policies can be combined with `and(..)`.

## Trust chain

A card is verified with a chain of two certificates, the public key of the issuer (from the participant metadata) and the card certificate on the chip, followed by a signature made by the card. See [Trust chain](docs/TRUST_CHAIN.md) for an illustration and for what each factory checks.

## Threads and performance

The factories are thread safe and are meant to be created **once** and shared by all threads and card readers. The first card is much slower than the next ones, unless the application warms up first. See [Performance](docs/PERFORMANCE.md) for how to warm up, with measurements from a phone.

## Testing
A `test` artifact for analyzing and/or testing cards are included with the project.

<details>
  <summary>Example output 1 (TLV)</summary>

```
[main] INFO no.entur.abt.bob.mts7.test.record.TlvCborPrinterCard - -> Select application null: 00A4040006A00000078101
[main] INFO no.entur.abt.bob.mts7.test.record.TlvCborPrinterCard - <- Command correct. :64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000 (in 22ms) 
64 29 
      6E 27 -- Application related data 
            4F 10 -- Application Identifier (ADF Name) 
                  A0 00 00 07 81 01 01 00 0A 00 00 17 5F 96 B6 1D 
            7A 05 -- Security-support data 
                  93 03 -- Digital signature counter 
                        00 00 24 
            8A 01 -- Life-cycle status byte 
                  00 
            7F 66 08 -- Extended Length Information 
                     02 02 -- Maximum APDU length
                           01 05 
                     02 02 -- Maximum APDU length
                           01 02
```
</details>

<details>
  <summary>Example output 2 (CBOR)</summary>

```
[main] INFO no.entur.abt.bob.mts7.test.record.TlvCborPrinterCard - -> Get next data: 00CC7F21000000
[main] INFO no.entur.abt.bob.mts7.test.record.TlvCborPrinterCard - <- A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000 (in 37ms)
{
  "v" : "1",
  "p" : [ {
    "alg" : "ES256",
    "iid" : "10",
    "kid" : "10:20230213",
    "miv" : "6",
    "nbf" : "20230616T110236Z",
    "tpk" : {
      "kty" : "EC",
      "crv" : "P-256",
      "x" : "gRE1EKw-cG_7AUC0h57-T5WYAnQcDWYru7JwmLGgVfo",
      "y" : "pkQkjVch2T2da_X-KShsQAQZ0jGHZH1ywZGTdVdb6dQ"
    }
  }, { }, "A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C4603" ]
}
</details>

## Links:

 - https://github.com/entur/abt-bob-openapi
 - https://bitbucket.org/samtrafiken/workspace/projects/BOBS
 - https://samtrafiken.atlassian.net/wiki/spaces/BOB/pages/110985249/How+does+it+work
 - https://samtrafiken.atlassian.net/wiki/spaces/BOB/pages/1375404281/MTS+Documentation
 - https://github.com/kirei/mts7-javacard
