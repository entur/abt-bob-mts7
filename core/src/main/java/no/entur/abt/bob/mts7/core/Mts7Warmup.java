package no.entur.abt.bob.mts7.core;

import java.security.Provider;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.api.pm.model.JwkPublic;
import no.entur.abt.bob.mts7.core.pki.IccPublicKey;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;
import no.entur.abt.bob.mts7.core.pki.IssuerSignatureFactory;
import no.entur.abt.bob.mts7.core.pki.ParticipantPublicKeys;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

/**
 * Do the work which otherwise is done for the first card, i.e. load classes, initialize the security provider and let the JVM compile the hot code. The first
 * card is much slower than the rest (tens of milliseconds on a desktop, more on a phone), which is a long time for a card which might leave the reader.
 * <p>
 * Pass in the factories of the application: a genuine card (its public data only, with its issuer key) is run through them just like a card from a reader, so
 * the objects which are warmed up are the ones which will be used, including the caches which they build on first use. The number of times is up to you, as
 * code which has been run only once is not necessarily compiled: use {@linkplain Builder#withIterations(int)},
 * {@linkplain Builder#withDuration(long, TimeUnit)} or both (whichever comes first). With neither, the card is run through once.
 * <p>
 * Warm-up is best effort: it never throws, and a failure only means that the first card is slower. Look at the {@linkplain Mts7WarmupResult} to find out what
 * did not work.
 *
 * <pre>
 * Mts7WarmupResult result = Mts7Warmup.newBuilder().withVerifyFactory(verifyFactory).withParticipantPublicKeys(keys).withIterations(20).build().warmUp();
 * </pre>
 *
 * An instance can be used more than once, and from several threads. It is a {@linkplain Runnable} for the executor of the application, which also decides which
 * thread (and priority) is used: the library does not create any threads.
 */

public class Mts7Warmup implements Runnable {

	private static final Logger LOGGER = LoggerFactory.getLogger(Mts7Warmup.class);

	// the responses (without the status words) of a genuine card to 'select application', 'get next data' and 'internal authenticate' (the challenge being 32
	// zero bytes)
	private static final byte[] SAMPLE_SELECT_APPLICATION_PAYLOAD = ByteArrayHexStringConverter
			.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F66080202010502020102");
	private static final byte[] SAMPLE_GET_DATA_PAYLOAD = ByteArrayHexStringConverter.hexStringToByteArray(
			"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C4603");
	private static final byte[] SAMPLE_INTERNAL_AUTHENTICATE_OUTPUT = ByteArrayHexStringConverter.hexStringToByteArray(
			"DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE34");

	// the public key of the issuer of the sample card (which is the one that signed it: the signature does not expire)
	private static final long SAMPLE_ISSUER_PID = 10;
	private static final String SAMPLE_ISSUER_KID = "10:20230213";
	private static final String SAMPLE_ISSUER_X = "FloU5pook5_F65GdE-eDMjreSztdKkPlVN3ZjaCAC90";
	private static final String SAMPLE_ISSUER_Y = "XXK-ydQMUjN4pgraVyPl896T4eFZeOh6dbsEQj8Xnt0";

	public static Builder newBuilder() {
		return new Builder();
	}

	public static class Builder {

		private LenientMts7CardFactory lenientFactory;
		private VerifyKeyPairMts7CardFactory keyPairFactory;
		private VerifyMts7CardFactory verifyFactory;
		private ParticipantPublicKeys participantPublicKeys;
		private Collection<Long> participantIds;

		private Integer iterations;
		private Long durationNanos;

		/**
		 * @param factory factory to warm up
		 * @return this
		 */

		public Builder withLenientFactory(LenientMts7CardFactory factory) {
			this.lenientFactory = factory;
			return this;
		}

		/**
		 * @param factory factory to warm up
		 * @return this
		 */

		public Builder withKeyPairFactory(VerifyKeyPairMts7CardFactory factory) {
			this.keyPairFactory = factory;
			return this;
		}

		/**
		 * Warm up a factory which checks the trust chain. This does not need the issuer keys of the factory (they might not contain the issuer of the sample
		 * card, and keys are created on demand): the sample card is verified using the helpers of the factory and its own issuer key. Use
		 * {@linkplain #withParticipantPublicKeys(ParticipantPublicKeys)} to create the real keys.
		 *
		 * @param factory factory to warm up
		 * @return this
		 */

		public Builder withVerifyFactory(VerifyMts7CardFactory factory) {
			this.verifyFactory = factory;
			return this;
		}

		/**
		 * Create all the issuer keys, which otherwise are created when first used. Done once, not for each iteration.
		 *
		 * @param participantPublicKeys keys
		 * @return this
		 */

		public Builder withParticipantPublicKeys(ParticipantPublicKeys participantPublicKeys) {
			this.participantPublicKeys = participantPublicKeys;
			return this;
		}

		/**
		 * Create the issuer keys of these participants only (those which are expected for the card readers of this device); the others are still created when
		 * first used. Unknown participants are ignored.
		 *
		 * @param participantPublicKeys keys
		 * @param participantIds        participant ids
		 * @return this
		 */

		public Builder withParticipantPublicKeys(ParticipantPublicKeys participantPublicKeys, Collection<Long> participantIds) {
			this.participantPublicKeys = participantPublicKeys;
			this.participantIds = participantIds;
			return this;
		}

		/**
		 * Run the sample card through the factories this many times. More is not necessarily better: use the first card on the real device to find out.
		 *
		 * @param iterations number of times, at least one
		 * @return this
		 */

		public Builder withIterations(int iterations) {
			if (iterations < 1) {
				throw new IllegalArgumentException("Expected at least one iteration, got " + iterations);
			}
			this.iterations = iterations;
			return this;
		}

		/**
		 * Keep running the sample card through the factories for this long. A run which has started is completed, so the duration is exceeded by up to one run.
		 * Combined with {@linkplain #withIterations(int)}, whichever comes first applies.
		 *
		 * @param duration duration, more than zero
		 * @param unit     unit
		 * @return this
		 */

		public Builder withDuration(long duration, TimeUnit unit) {
			if (duration <= 0) {
				throw new IllegalArgumentException("Expected a duration, got " + duration);
			}
			this.durationNanos = unit.toNanos(duration);
			return this;
		}

		/**
		 * @return a warm-up
		 * @throws IllegalStateException if there is nothing to warm up
		 */

		public Mts7Warmup build() {
			if (lenientFactory == null && keyPairFactory == null && verifyFactory == null && participantPublicKeys == null) {
				throw new IllegalStateException("Nothing to warm up: pass in a factory or the participant public keys");
			}
			return new Mts7Warmup(this);
		}
	}

	private interface Step {
		void run(Mts7ApduPayloads payloads) throws Exception;
	}

	private static class NamedStep {

		private final String name;
		private final Step step;

		private NamedStep(String name, Step step) {
			this.name = name;
			this.step = step;
		}
	}

	private final LenientMts7CardFactory lenientFactory;
	private final VerifyKeyPairMts7CardFactory keyPairFactory;
	private final VerifyMts7CardFactory verifyFactory;
	private final ParticipantPublicKeys participantPublicKeys;
	private final Collection<Long> participantIds;

	// a limit on the number of iterations, which is also the number if there is no limit on time
	private final int maxIterations;
	// zero for none
	private final long durationNanos;

	private Mts7Warmup(Builder builder) {
		this.lenientFactory = builder.lenientFactory;
		this.keyPairFactory = builder.keyPairFactory;
		this.verifyFactory = builder.verifyFactory;
		this.participantPublicKeys = builder.participantPublicKeys;
		this.participantIds = builder.participantIds;

		this.durationNanos = builder.durationNanos != null ? builder.durationNanos : 0;
		if (builder.iterations != null) {
			this.maxIterations = builder.iterations;
		} else if (builder.durationNanos != null) {
			this.maxIterations = Integer.MAX_VALUE;
		} else {
			this.maxIterations = 1;
		}
	}

	/**
	 * Warm up. Never throws. This is cheap to call more than once, but it does the work each time.
	 *
	 * @return what was done and what did not work
	 */

	public Mts7WarmupResult warmUp() {
		long start = System.nanoTime();

		List<Exception> failures = new ArrayList<>();
		int iterations = 0;
		try {
			if (participantPublicKeys != null) {
				failures.addAll(participantIds != null ? participantPublicKeys.warmUp(participantIds) : participantPublicKeys.warmUp());
			}

			List<NamedStep> steps = createSteps();
			if (!steps.isEmpty()) {
				Mts7ApduPayloads payloads = createSamplePayloads();

				do {
					for (Iterator<NamedStep> iterator = steps.iterator(); iterator.hasNext();) {
						NamedStep step = iterator.next();
						try {
							step.step.run(payloads);
						} catch (Exception | LinkageError e) {
							// no point in trying again
							failures.add(new IllegalStateException("Unable to warm up " + step.name, e));
							iterator.remove();
						}
					}
					iterations++;
				} while (!steps.isEmpty() && iterations < maxIterations && !isDone(start) && !Thread.currentThread().isInterrupted());
			}
		} catch (Exception | LinkageError e) {
			failures.add(new IllegalStateException("Unable to warm up", e));
		}
		return new Mts7WarmupResult(iterations, System.nanoTime() - start, failures);
	}

	private boolean isDone(long start) {
		return durationNanos > 0 && System.nanoTime() - start >= durationNanos;
	}

	@Override
	public void run() {
		Mts7WarmupResult result = warmUp();
		if (result.isSuccess()) {
			LOGGER.debug("Warmed up: {}", result);
		} else {
			LOGGER.info("Warmed up with failures: {}", result);
			for (Exception failure : result.getFailures()) {
				LOGGER.info("Warm-up failure", failure);
			}
		}
	}

	private List<NamedStep> createSteps() {
		List<NamedStep> steps = new ArrayList<>();
		if (lenientFactory != null) {
			steps.add(new NamedStep("LenientMts7CardFactory", payloads -> {
				if (!lenientFactory.create(payloads).isVerifiedPrivateKeyPresent()) {
					throw new IllegalStateException("The private key of the sample card was not verified");
				}
			}));
		}
		if (keyPairFactory != null) {
			// throws if not verified
			steps.add(new NamedStep("VerifyKeyPairMts7CardFactory", payloads -> keyPairFactory.create(payloads)));
		}
		if (verifyFactory != null) {
			// the helpers of the factory, but not its keys: they might not contain the issuer of the sample card
			VerifyMts7CardFactory sampleFactory = new VerifyMts7CardFactory(createSampleIssuerKeys(verifyFactory.iccPublicKeyFactory.getProvider()),
					verifyFactory.iccPublicKeyFactory, verifyFactory.enricher, verifyFactory.cborMapper, verifyFactory.thumbprintFactory);

			// throws if not verified
			steps.add(new NamedStep("VerifyMts7CardFactory", payloads -> sampleFactory.create(payloads)));
		}
		return steps;
	}

	private static ParticipantPublicKeys createSampleIssuerKeys(Provider provider) {
		JwkPublic jwk = new JwkPublic().kty("EC").kid(SAMPLE_ISSUER_KID).crv("P-256").x(SAMPLE_ISSUER_X).y(SAMPLE_ISSUER_Y);

		Map<String, ParticipantPublicKeys.IssuerKey> keys = new HashMap<>();
		keys.put(SAMPLE_ISSUER_KID, new ParticipantPublicKeys.IssuerKey(jwk));

		Map<Long, ParticipantPublicKeys.Issuer> issuers = new HashMap<>();
		issuers.put(SAMPLE_ISSUER_PID, new ParticipantPublicKeys.Issuer("Sample", SAMPLE_ISSUER_PID, keys, new IssuerSignatureFactory(provider)));

		return new ParticipantPublicKeys(issuers);
	}

	private static Mts7ApduPayloads createSamplePayloads() {
		Mts7ApduPayloads payloads = new Mts7ApduPayloads();
		payloads.setSelectApplicationOutput(SAMPLE_SELECT_APPLICATION_PAYLOAD);
		payloads.setGetDataOutput(SAMPLE_GET_DATA_PAYLOAD);
		payloads.setInternalAuthenticateInput(new byte[32]);
		payloads.setInternalAuthenticateOutput(SAMPLE_INTERNAL_AUTHENTICATE_OUTPUT);
		return payloads;
	}

	/**
	 * Exercise the helpers used for each card, with the data of a genuine card. For those who have the helpers but not the factories (the processor factories);
	 * prefer {@linkplain #newBuilder()}.
	 *
	 * @param cborMapper          mapper
	 * @param enricher            card enricher
	 * @param iccPublicKeyFactory factory for the public key of the card
	 */

	public static void warmUp(CBORMapper cborMapper, Mts7CardEnricher enricher, IccPublicKeyFactory iccPublicKeyFactory) {
		try {
			Mts7Card card = new Mts7Card();

			Map<String, Object> header = parseSampleCard(cborMapper, enricher, card);

			IccPublicKey iccPublicKey = iccPublicKeyFactory.create(header);
			iccPublicKey.verify(new byte[32], SAMPLE_INTERNAL_AUTHENTICATE_OUTPUT);
		} catch (Exception | LinkageError e) {
			LOGGER.debug("Unable to warm up", e);
		}
	}

	/**
	 * Parse the data of a genuine card (its public data only) as the card factories do, so that the same classes and code paths are used for the first real
	 * card.
	 *
	 * @param cborMapper mapper
	 * @param enricher   card enricher
	 * @return the card
	 * @throws Exception if the sample could not be parsed
	 */

	static Mts7Card parseSampleCard(CBORMapper cborMapper, Mts7CardEnricher enricher) throws Exception {
		Mts7Card card = new Mts7Card();
		parseSampleCard(cborMapper, enricher, card);
		return card;
	}

	/**
	 * @return the issuer signature protected header of the sample card
	 */

	@SuppressWarnings("unchecked")
	private static Map<String, Object> parseSampleCard(CBORMapper cborMapper, Mts7CardEnricher enricher, Mts7Card card) throws Exception {
		enricher.enrichSelectApplicationResponsePayload(card, SAMPLE_SELECT_APPLICATION_PAYLOAD);

		Map<String, Object> outer = cborMapper.readValue(SAMPLE_GET_DATA_PAYLOAD, Map.class);

		byte[][] elements = cborMapper.readValue((byte[]) outer.get("p"), byte[][].class);

		Map<String, Object> header = null;

		// the last element is the signature
		for (int i = 0; i < elements.length - 1; i++) {
			Map<String, Object> element = cborMapper.readValue(elements[i], Map.class);
			if (header == null && !element.containsKey("did") && element.containsKey("kid") && element.containsKey("iid")) {
				header = element;
			}
		}
		if (header == null) {
			throw new IllegalStateException("No issuer signature protected header in the sample card");
		}
		return header;
	}

}
