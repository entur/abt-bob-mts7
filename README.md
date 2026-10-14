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

> **The guides are for clients only**, i.e. the code which talks to the card (for example a mobile app or a terminal). They do not cover the server which receives the commands and responses. Parsing and verifying those on a server is done with `core`; see [Performance](docs/PERFORMANCE.md#server) for how to share the factories there.

Select between three approaches:

 * [online only](#online-only)
 * [online with offline fallback](#online-with-offline-fallback)
 * [offline](#offline)

### Before you start

 * Add the artifact which you need (group id `no.entur.abt.bob.mts7`, use the latest release):
   * `simple-reader` for online only. It only depends on `api` and `simple-api`, so there is no parsing or crypto in the client.
   * `reader` for online with offline fallback and for offline. It brings `core` and `simple-reader`.
 * Implement your own class of type `Mts7Exchange` for talking to the card (`getTagId()` and `transceive(byte[])`). The library sends the commands and checks the status codes of the responses.
 * Create the factories **once** and share them between card readers and threads, see [Performance](docs/PERFORMANCE.md).

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
   * some commands are split due to max transceive length (so checking the response status code is necessary: `61xx` means that there is more data, which is fetched with GET RESPONSE)
 * post to backend as a command/response train
   * split commands can be submitted together or in (original) parts; the library keeps the original parts

In other words, no parsing or crypto operations are necessary in client.

Implementation using 'thin' client:

 * add `simple-reader` artifact
 * Implement your own class of type `Mts7Exchange` for talking to the card
 * Create an instance of `Mts7ApduExchangesFactory`
 * Create `Mts7ApduExchanges` from `Mts7ApduExchangesFactory.createCard(..)`. Pass the response to *select application* if your platform has already selected the application, or null to have the library do it.
 * Post the exchanges (`getTagId()` and `getExchanges()`) to the backend.

`createCard(..)` throws `IOException` if the card cannot be reached (for example if it is moved away from the reader) and a `Mts7Exception` if the card answers something unexpected (`UnableToSelectApplicationException` if the application cannot be selected, `UnexpectedCardResponseException` for other status codes).

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
   * Most secure: `VerifyTrustChainMts7ProcessorFactory` (requires the public keys of the issuers via `ParticipantPublicKeys`, which you build from the participant metadata) or
   * Less secure: `VerifyKeyPairMts7ProcessorFactory` (only checks that the card has the private key, not who issued it)
 * Create `InFlightMts7CardFactory` 
 * Create `InFlightMts7Card` from `InFlightMts7CardFactory.create(..)` which contains the `Mts7ApduExchanges`. It is `Closeable`: close it when done (try-with-resources), or the processor keeps waiting for the card (for at most a minute).
 * Post the exchanges to the backend. If this fails, then
 * Call on `InFlightMts7Card.getMts7Card(timeout)` (in milliseconds; zero waits until the processing has finished) to obtain a `Mts7Card`
 * Process card details (thumbprint, serial etc) locally

`getMts7Card(..)` throws `UnableToVerifyKeyPairException` if the card cannot be trusted: it did not prove that it has the private key, or (for the trust chain) its issuer is not among the public keys. The exception has the card as far as it was read, in `getResult()`, where `isVerifiedTrustChain()` tells the reasons apart. `UnableToVerifyTrustChainException` is declared too, but in practice a card from an unknown issuer is reported by the former.

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
        Mts7Card card = inFlight.getMts7Card(1000); // wait for at most a second

        useLocally(card);
    }
}
```
</details>

### Offline

 * Like above, just don't post anything to the server.
 * Or read the card first and process it afterwards: `Mts7ApduPayloadsFactory` sorts out the responses of the exchanges, and `VerifyMts7CardFactory` verifies the card (`VerifyKeyPairMts7CardFactory` if there are no public keys). For the details of a card which cannot be verified, `LenientMts7ApduPayloadsFactory` and `LenientMts7CardFactory` extract as much as they can, also from a partial read, instead of rejecting it; nothing which they return can be trusted.

<details>
  <summary>Code example</summary>

```java
// once: shared by all card readers and threads ('keys' are the ParticipantPublicKeys, see above)
Mts7ApduExchangesFactory exchangesFactory = new Mts7ApduExchangesFactory();
Mts7ApduPayloadsFactory payloadsFactory = new Mts7ApduPayloadsFactory();
VerifyMts7CardFactory cardFactory = new VerifyMts7CardFactory(keys);

// for each card, where 'exchange' is the Mts7Exchange for the card
Mts7ApduExchanges exchanges = exchangesFactory.createCard(exchange, null);
Mts7ApduPayloads payloads = payloadsFactory.createCard(exchanges);

// throws if the card does not have the private key, or was not issued by one of the issuers of the keys
Mts7Card card = cardFactory.create(payloads);
```
</details>

## Threads and performance

The factories are thread safe and are meant to be created **once** and shared by all threads and card readers. The first card is much slower than the next ones, unless the application warms up first. See [Performance](docs/PERFORMANCE.md) for what is shared and what is for one card, recipes for a server and for a mobile device, and how to warm up (with measurements from a phone).

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
