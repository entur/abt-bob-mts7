# Performance

Using the library from several threads and card readers, and making the first card as fast as the next ones.

## Threads and reuse

Create the factories **once** and share them between all threads and card readers; they are thread safe, and they are where the expensive objects live (the CBOR mapper, the issuer keys, the security provider setup).

Only the objects for a single card are created for each card, and used by one thread at a time. In code (`Backend` stands for your own code which posts to the server):

```java
public class Mts7Reading {

    // Created once, when the application starts, and shared by all threads and card readers
    private final Mts7ApduExchangesFactory exchangesFactory = new Mts7ApduExchangesFactory();
    private final Mts7ApduPayloadsFactory payloadsFactory = new Mts7ApduPayloadsFactory();
    private final VerifyMts7CardFactory cardFactory;
    private final InFlightMts7CardFactory inFlightCardFactory;

    public Mts7Reading(ParticipantPublicKeys keys, Executor executor) throws Exception {
        // the keys are shared too, as are the issuer keys which they create
        this.cardFactory = new VerifyMts7CardFactory(keys);
        this.inFlightCardFactory = new InFlightMts7CardFactory(new VerifyTrustChainMts7ProcessorFactory(keys, executor));
    }

    // Called by any thread, for each card. The Mts7Exchange of the card, and what is created in here (the
    // exchanges, the payloads and the Mts7Card), is for this card only and is used by one thread at a
    // time, so do not keep it for the next card.
    public Mts7Card read(Mts7Exchange exchange) throws Exception {
        Mts7ApduExchanges exchanges = exchangesFactory.createCard(exchange, null);
        Mts7ApduPayloads payloads = payloadsFactory.createCard(exchanges);

        return cardFactory.create(payloads);
    }

    // The same, but with a processor working on the card while it is read. The processor is for this card
    // only, and so is the InFlightMts7Card, which closes it.
    public void readAndPost(Mts7Exchange exchange, Backend backend) throws Exception {
        try (InFlightMts7Card inFlight = inFlightCardFactory.create(exchange, null)) {
            Mts7ApduExchanges exchanges = inFlight.getMts7ApduExchanges();

            backend.post(exchanges.getTagId(), exchanges.getExchanges());
        }
    }
}
```

The other factories are shared in the same way: `VerifyKeyPairMts7CardFactory`, `LenientMts7CardFactory`, `VerifyKeyPairMts7ProcessorFactory`, `ProcessorMts7ApduExchangesFactory`, and the helpers which they use (`IccPublicKeyFactory`, `IssuerSignatureFactory`, `ThumbprintFactory`, `Mts7CardEnricher`), as are the `IssuerPublicKey`s which `ParticipantPublicKeys` creates. `IccPublicKeyBuilder` is for one card (the card factories create one for each card).

Notes:

 * `IccPublicKey` is the key of one card, but is thread safe like `IssuerPublicKey`: both verify with a new `Signature` each time, so there is nothing to restore after a failed verification.
 * A processor can be given its input by the thread which reads the card, and be closed or waited for from any thread. `InFlightMts7Card` is closeable: close it when done, or the processor waits (at most one minute) for a card which is not there anymore.
 * The test support classes (`test` artifact: recordings, playback, pretty printers) are for one card at a time.
 * Do not modify the command constants (`Mts7ApduExchangesFactory.SELECT_BOB_COMMAND` etc.); they are shared.

### Server

Create `ParticipantPublicKeys` and a `VerifyMts7CardFactory` once (for example at startup), and call `create(..)` from any number of threads. Warm them up when starting (see [Warming up](#warming-up-with-mts7warmup)), so that the first request is not slower than the rest.

### Mobile device with one or more readers

Create the factories once when the application starts, keep them for as long as the application lives, and read cards on whichever thread reads them (up to the number of readers at the same time). The first card is much slower than the next ones as classes are loaded and code compiled, so warm up in the background first. On a desktop JVM this takes the first card from about 50 ms to about 4 ms:

```java
ParticipantPublicKeys keys = ParticipantPublicKeys.newBuilder().withParticipants(participants).build();
ExecutorService executor = Executors.newCachedThreadPool(); // yours: shut it down when the application stops

// the helpers which the factory uses, so that they can be warmed up
IccPublicKeyFactory iccPublicKeyFactory = new IccPublicKeyFactory();
Mts7CardEnricher enricher = new Mts7CardEnricher();
CBORMapper cborMapper = new CBORMapper();
ThumbprintFactory thumbprintFactory = new ThumbprintFactory(null);

VerifyTrustChainMts7ProcessorFactory processorFactory = new VerifyTrustChainMts7ProcessorFactory(keys, iccPublicKeyFactory, enricher, cborMapper, thumbprintFactory, executor);
InFlightMts7CardFactory factory = new InFlightMts7CardFactory(processorFactory);

// in the background: loads classes, initializes the security provider and creates the issuer keys
executor.execute(Mts7Warmup.newBuilder().withHelpers(iccPublicKeyFactory, enricher, cborMapper, thumbprintFactory).withParticipantPublicKeys(keys).build());
```

 * Use the constructors which take a `Provider` if the application uses its own security provider (for example Conscrypt or Bouncy Castle).
 * The processors run on the threads of an `Executor` which you provide to the processor factory: the library does not create any executors or threads of its own, so you own it and shut it down. You can share it with the rest of the application. A processor waits for the reader to give it input, so the executor must have a thread for each card which is being read at the same time (for example a cached thread pool, not a pool which is smaller than the number of readers), and must not run the processor on the thread which reads the card. A processor stops waiting for the card after a minute, but if the threads of your executor must not keep the JVM alive, use daemon threads.

## Warming up with `Mts7Warmup`

`Mts7Warmup` (in the package `no.entur.abt.bob.mts7.core.warmup`) is the only place for warming up: the factories have no warm-up of their own. It takes the factories of the application (or the helpers which they share, for the processor factories) and runs a genuine card (its public data only, with the public key of its issuer) through them like a card from a reader, so the objects which are warmed up are the ones which will be used. It needs no keys of its own, so it also works if the issuer of the sample card is not among your participants. It never throws; look at the `Mts7WarmupResult` to find out what did not work.

```java
Mts7Warmup warmup = Mts7Warmup.newBuilder()
    .withVerifyFactory(verifyFactory)   // and/or withKeyPairFactory(..), withLenientFactory(..), withHelpers(..)
    .withParticipantPublicKeys(keys)    // optional: also create the issuer keys (or keys, Arrays.asList(10L, 11L))
    .withIterations(3)                  // and/or .withDuration(100, TimeUnit.MILLISECONDS), whichever comes first
    .build();

executor.execute(warmup);               // it is a Runnable (the result is logged); or call warmup.warmUp() for the result
```

With neither iterations nor a duration the card is run through once. Code which has run once is not necessarily compiled, so you can run it more times; more is not always better. First card on a Pixel 9 (Android 16, debug build, each in a new process; a card after the first takes 1.2 to 1.4 ms):

| Warm-up | Warm-up time | First card, lenient | First card, trust chain |
| --- | --- | --- | --- |
| none | | 32 ms | 24 ms |
| 1 iteration | 31 / 22 ms | 1.5 ms | 2.2 ms |
| 3 iterations | 32 / 26 ms | 1.2 ms | 1.9 ms |
| 30 iterations | 71 / 62 ms | 1.1 ms | 1.9 ms |
| 300 iterations | 345 / 364 ms | 0.6 ms | 1.0 ms |
| 3 iterations + all 192 issuer keys | 130 ms | | 1.3 ms |

Nearly all of the gain is in the first iteration; the next ones help a little. Only 300 iterations got below the speed of the later cards of the other runs, probably because the runtime then compiles the hot code, and that costs hundreds of milliseconds of processor time (100 iterations was not enough). The remaining 0.5 ms of the trust chain is the creation of the key of the issuer of the card, which is what `withParticipantPublicKeys(..)` is for. Measure with the build of your application, as the numbers depend on the device and on how the application is compiled.
