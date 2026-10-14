# Performance

Making the first card as fast as the next ones.

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
