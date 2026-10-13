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
Select between three approaches:

 * online only
 * online with offline fallback
 * offline

### Online only
Overview:
 
 * issue three (logical) commands and store command/responses as raw APDUs
   * some commands are split due to max transcieve length (so checking the response status code is necessary)
 * post to backend as a command/response train
   * split commands can be submitted together or in (original) parts 

In other words, no parsing or crypto operations are necessary in client.

Implementation using 'thin' client:

 * add `simple-reader` artifact
 * Implement your own class of type `Mts7Exchange` for talking to the card
 * Create an instance of `Mts7ApduExchangesFactory`
 * Create `Mts7ApduExchanges` from `Mts7ApduExchangesFactory.createCard(..)`,
 * Post the exchanges to the backend.

### Online with offline fallback

Overview:
 
 * (optional) retrieve public keys and blacklists
 * issue three (logical) commands and store command/responses as raw APDUs
   * some commands are split due to max transcieve length
 * post to backend as a command/response train
   * split commands can be submitted together or in (original) parts
 * if server call fails, decode and verify card locally
   * without talking to the card again 

Implementation:

 * add `reader` artifact
 * Implement your own class of type `Mts7Exchange` for talking to the card
 * Create a `Mts7ProcessorFactory`: 
   * Most secure: `VerifyTrustChainMts7ProcessorFactory` (requires root certificates via `ParticipantPublicKeys`) or
   * Less secure: `VerifyKeyPairMts7ProcessorFactory`
 * Create `InFlightMts7CardFactory` 
 * Create `InFlightMts7Card` from `InFlightMts7CardFactory.create(..)` which contains the `Mts7ApduExchanges` 
 * Post the exchanges to the backend. It this fails, then
 * Call on `InFlightMts7Card.getMts7Card(..)` to obtain a `Mts7Card`
 * Process card details (thumbprint, serial etc) locally

### Offline

 * Like above, just don't post anything to the server.

## Threads and reuse

Create the factories **once** and share them between all threads and card readers; they are thread safe, and they are where the expensive objects live (the CBOR mapper, the issuer keys, the security provider setup). Only the objects for a single card are per card.

| Shared by all threads (create once) | For one card, one thread at a time (create for each card) |
| --- | --- |
| `ParticipantPublicKeys`, `IssuerPublicKey` | `Mts7ApduPayloads`, `Mts7Card` |
| `VerifyMts7CardFactory`, `VerifyKeyPairMts7CardFactory`, `LenientMts7CardFactory` | `IccPublicKey`, `IccPublicKeyBuilder` |
| `VerifyTrustChainMts7ProcessorFactory`, `VerifyKeyPairMts7ProcessorFactory` | the `Mts7Processor` created by a processor factory |
| `InFlightMts7CardFactory`, `ProcessorMts7ApduExchangesFactory`, `Mts7ApduExchangesFactory` | `InFlightMts7Card`, `Mts7ApduExchanges`, your `Mts7Exchange` |
| `IccPublicKeyFactory`, `IssuerSignatureFactory`, `ThumbprintFactory`, `Mts7CardEnricher` | |

Notes:

 * A processor can be given its input by the thread which reads the card, and be closed or waited for from any thread. `InFlightMts7Card` is closeable: close it when done, or the processor waits (at most one minute) for a card which is not there anymore.
 * The test support classes (`test` artifact: recordings, playback, pretty printers) are for one card at a time.
 * Do not modify the command constants (`Mts7ApduExchangesFactory.SELECT_BOB_COMMAND` etc.); they are shared.

### Server

Create `ParticipantPublicKeys` and a `VerifyMts7CardFactory` once (for example at startup), and call `create(..)` from any number of threads. Call `warmUp()` on both when starting, so that the first request is not slower than the rest.

### Mobile device with one to three readers

Create the factories once when the application starts, keep them for as long as the application lives, and read cards on whichever thread reads them (up to the number of readers at the same time). The first card is much slower than the next ones as classes are loaded and code compiled, so warm up in the background first. On a desktop JVM this takes the first card from about 50 ms to about 4 ms:

```java
ParticipantPublicKeys keys = ParticipantPublicKeys.newBuilder().withParticipants(participants).build();
ExecutorService executor = Executors.newCachedThreadPool(); // yours: shut it down when the application stops
VerifyTrustChainMts7ProcessorFactory processorFactory = new VerifyTrustChainMts7ProcessorFactory(keys, executor);
InFlightMts7CardFactory factory = new InFlightMts7CardFactory(processorFactory);

new Thread(() -> {
    keys.warmUp();             // creates the issuer keys, and returns those which could not be created
                               // (or keys.warmUp(Arrays.asList(10L, 11L)) for the participants which are expected)
    processorFactory.warmUp(); // loads classes, initializes the security provider
}).start();
```

 * Use the constructors which take a `Provider` if the application uses its own security provider (for example Conscrypt or Bouncy Castle).
 * The processors run on the threads of an `Executor` which you provide to the processor factory: the library does not create any executors or threads of its own, so you own it and shut it down. You can share it with the rest of the application. A processor waits for the reader to give it input, so the executor must have a thread for each card which is being read at the same time (for example a cached thread pool, not a pool which is smaller than the number of readers), and must not run the processor on the thread which reads the card. A processor stops waiting for the card after a minute, but if the threads of your executor must not keep the JVM alive, use daemon threads.

### Upgrading from 2.x

The next major version has these breaking changes:

 * `IssuerPublicKey` is created from a `PublicKey` (see `IssuerSignatureFactory.createIssuerPublicKey(..)`); the constructor which took a `Signature` is gone, as are `IssuerSignatureFactory.create(..)` and the `Signature` field.
 * The protected fields `ThumbprintFactory.messageDigest` and `Mts7CardEnricher.pullParser` are gone; the objects are created when needed.
 * The processors extend `AbstractMts7Processor`. The protected `thread` field is gone, as are the (unused) `algorithmExtractor` and `timeout` fields. A processor which is closed before it is started never starts, and `start()` and `close()` can be called more than once.
 * `waitForVerify(..)` returns (and the exceptions carry) a snapshot of the card if the processor has not finished, so the card does not change after it was returned.
 * The processors and the processor factories require an `Executor`, which you provide and shut down. The constructors without one, which started a new thread for each processor, are gone.
 * `IccPublicKey` and the processors are documented as for one card only, and `VerifyMts7CardFactory`, `VerifyKeyPairMts7CardFactory` and `LenientMts7CardFactory` are thread safe (do not create one for each thread or card).

### Testing
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
