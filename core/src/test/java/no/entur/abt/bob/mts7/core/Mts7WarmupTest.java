package no.entur.abt.bob.mts7.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.api.pm.model.JwkPublic;
import no.entur.abt.bob.api.pm.model.ParticipantMetadata;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;
import no.entur.abt.bob.mts7.core.pki.IssuerPublicKey;
import no.entur.abt.bob.mts7.core.pki.IssuerSignatureFactory;
import no.entur.abt.bob.mts7.core.pki.ParticipantPublicKeys;
import no.entur.abt.bob.mts7.core.pki.ThumbprintFactory;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

public class Mts7WarmupTest {

	private static byte[] fromResponseApdu(String hex) {
		byte[] response = ByteArrayHexStringConverter.hexStringToByteArray(hex);

		byte[] payload = new byte[response.length - 2];
		System.arraycopy(response, 0, payload, 0, payload.length);
		return payload;
	}

	private Mts7ApduPayloads payloads() {
		Mts7ApduPayloads payloads = new Mts7ApduPayloads();
		payloads.setSelectApplicationOutput(fromResponseApdu("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000"));
		payloads.setGetDataOutput(fromResponseApdu(
				"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000"));
		payloads.setInternalAuthenticateInput(
				ByteArrayHexStringConverter.hexStringToByteArray("0000000000000000000000000000000000000000000000000000000000000000"));
		payloads.setInternalAuthenticateOutput(fromResponseApdu(
				"DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000"));
		return payloads;
	}

	private List<ParticipantMetadata> readParticipantMetadata(ParticipantMetadata... additional) throws Exception {
		InputStream is = getClass().getResourceAsStream("/participantMetadata.json");
		List<ParticipantMetadata> participantMetadata = new ArrayList<>(Arrays.asList(new ObjectMapper().readValue(is, ParticipantMetadata[].class)));
		assertFalse(participantMetadata.isEmpty());
		participantMetadata.addAll(Arrays.asList(additional));
		return participantMetadata;
	}

	@Test
	public void testWarmUpDoesNotAffectTheResult() throws Exception {
		ParticipantPublicKeys participantPublicKeys = ParticipantPublicKeys.newBuilder().withParticipants(readParticipantMetadata()).build();

		VerifyMts7CardFactory factory = new VerifyMts7CardFactory(participantPublicKeys);

		Mts7Warmup warmup = Mts7Warmup.newBuilder().withVerifyFactory(factory).withParticipantPublicKeys(participantPublicKeys).build();

		// harmless to repeat, and to run on several threads
		assertTrue(warmup.warmUp().isSuccess());
		assertTrue(warmup.warmUp().isSuccess());

		Mts7Card card = factory.create(payloads());

		assertTrue(card.isVerifiedPrivateKeyPresent());
		assertTrue(card.isVerifiedTrustChain());
		assertEquals("0000175F96B61D", ByteArrayHexStringConverter.toHexString(card.getSerial()));
	}

	@Test
	public void testWarmUpOtherFactories() throws Exception {
		VerifyKeyPairMts7CardFactory keyPair = new VerifyKeyPairMts7CardFactory();
		LenientMts7CardFactory lenient = new LenientMts7CardFactory();

		Mts7WarmupResult result = Mts7Warmup.newBuilder().withKeyPairFactory(keyPair).withLenientFactory(lenient).build().warmUp();
		assertTrue(result.isSuccess(), result.getFailures().toString());

		assertTrue(keyPair.create(payloads()).isVerifiedPrivateKeyPresent());
		assertTrue(lenient.create(payloads()).isVerifiedPrivateKeyPresent());
	}

	private ParticipantPublicKeys readKeys(ParticipantMetadata... additional) throws Exception {
		return ParticipantPublicKeys.newBuilder().withParticipants(readParticipantMetadata(additional)).build();
	}

	private Mts7Warmup.Builder allFactories() throws Exception {
		// the keys of the factory know nothing about the issuer of the sample card
		return Mts7Warmup.newBuilder()
				.withLenientFactory(new LenientMts7CardFactory())
				.withKeyPairFactory(new VerifyKeyPairMts7CardFactory())
				.withVerifyFactory(new VerifyMts7CardFactory(ParticipantPublicKeys.newBuilder().build()));
	}

	@Test
	public void testOneIterationByDefault() throws Exception {
		Mts7WarmupResult result = allFactories().build().warmUp();

		assertTrue(result.isSuccess(), result.getFailures().toString());
		assertEquals(1, result.getIterations());
	}

	@Test
	public void testIterations() throws Exception {
		Mts7WarmupResult result = allFactories().withIterations(5).build().warmUp();

		assertTrue(result.isSuccess(), result.getFailures().toString());
		assertEquals(5, result.getIterations());
		assertTrue(result.getElapsedNanos() > 0);
	}

	@Test
	public void testDurationOnlyKeepsGoingUntilItIsUp() throws Exception {
		// the first run in a JVM can take longer than the duration, which then is used up by a single iteration
		allFactories().build().warmUp();

		Mts7WarmupResult result = allFactories().withDuration(50, TimeUnit.MILLISECONDS).build().warmUp();

		assertTrue(result.isSuccess(), result.getFailures().toString());
		assertTrue(result.getIterations() > 1, "Iterations: " + result.getIterations());
		assertTrue(result.getElapsed(TimeUnit.MILLISECONDS) >= 50);
	}

	@Test
	public void testWhicheverComesFirst() throws Exception {
		// iterations first
		Mts7WarmupResult iterations = allFactories().withIterations(3).withDuration(1, TimeUnit.HOURS).build().warmUp();
		assertEquals(3, iterations.getIterations());

		// duration first (see above for the first run)
		Mts7WarmupResult duration = allFactories().withIterations(100_000_000).withDuration(30, TimeUnit.MILLISECONDS).build().warmUp();
		assertTrue(duration.isSuccess(), duration.getFailures().toString());
		assertTrue(duration.getIterations() > 1 && duration.getIterations() < 100_000_000, "Iterations: " + duration.getIterations());
		assertTrue(duration.getElapsed(TimeUnit.MILLISECONDS) >= 30);
	}

	@Test
	public void testNothingToWarmUp() {
		assertThrows(IllegalStateException.class, () -> Mts7Warmup.newBuilder().build());
	}

	@Test
	public void testInvalidLimits() {
		assertThrows(IllegalArgumentException.class, () -> Mts7Warmup.newBuilder().withIterations(0));
		assertThrows(IllegalArgumentException.class, () -> Mts7Warmup.newBuilder().withIterations(-1));
		assertThrows(IllegalArgumentException.class, () -> Mts7Warmup.newBuilder().withDuration(0, TimeUnit.SECONDS));
		assertThrows(IllegalArgumentException.class, () -> Mts7Warmup.newBuilder().withDuration(-1, TimeUnit.SECONDS));
	}

	@Test
	public void testVerifyFactoryIsWarmedUpWithTheKeyOfTheSampleIssuer() throws Exception {
		// reaches the issuer signature without having any keys: the factory would throw if the trust chain was not verified
		Mts7WarmupResult result = Mts7Warmup.newBuilder()
				.withVerifyFactory(new VerifyMts7CardFactory(ParticipantPublicKeys.newBuilder().build()))
				.build()
				.warmUp();

		assertTrue(result.isSuccess(), result.getFailures().toString());
		assertEquals(1, result.getIterations());
	}

	@Test
	public void testParticipantPublicKeys() throws Exception {
		Mts7WarmupResult result = Mts7Warmup.newBuilder().withParticipantPublicKeys(readKeys()).build().warmUp();

		// nothing to run the card through
		assertTrue(result.isSuccess(), result.getFailures().toString());
		assertEquals(0, result.getIterations());
	}

	@Test
	public void testParticipantPublicKeysFailuresAreReported() throws Exception {
		JwkPublic invalid = new JwkPublic().kty("EC").kid("99:invalid").crv("P-256").x("AAAA").y("AAAA");
		ParticipantPublicKeys keys = readKeys(new ParticipantMetadata().pid(99L).organisationName("Invalid").addMtbPublicKeysItem(invalid));

		Mts7WarmupResult everyone = allFactories().withParticipantPublicKeys(keys).build().warmUp();
		assertEquals(1, everyone.getFailures().size());
		assertTrue(everyone.getFailures().get(0).getMessage().contains("99:invalid"), everyone.getFailures().get(0).getMessage());
		// the rest still works
		assertEquals(1, everyone.getIterations());

		Mts7WarmupResult expected = allFactories().withParticipantPublicKeys(keys, Arrays.asList(10L, 99L)).build().warmUp();
		assertEquals(1, expected.getFailures().size());

		Mts7WarmupResult others = allFactories().withParticipantPublicKeys(keys, Arrays.asList(10L, 11L, 12345L)).build().warmUp();
		assertTrue(others.isSuccess(), others.getFailures().toString());
	}

	@Test
	public void testFailureIsReportedAndTheOthersAreStillWarmedUp() throws Exception {
		LenientMts7CardFactory failing = new LenientMts7CardFactory() {
			@Override
			public Mts7Card create(Mts7ApduPayloads card) throws UnableToVerifyKeyPairException {
				throw new IllegalArgumentException("Broken");
			}
		};

		Mts7WarmupResult result = Mts7Warmup.newBuilder()
				.withLenientFactory(failing)
				.withKeyPairFactory(new VerifyKeyPairMts7CardFactory())
				.withIterations(5)
				.build()
				.warmUp();

		assertFalse(result.isSuccess());
		assertEquals(1, result.getFailures().size());
		assertTrue(result.getFailures().get(0).getMessage().contains("LenientMts7CardFactory"), result.getFailures().get(0).getMessage());
		assertEquals("Broken", result.getFailures().get(0).getCause().getMessage());

		// the other factory was run through all of the iterations
		assertEquals(5, result.getIterations());
	}

	@Test
	public void testLinkageErrorIsReportedNotThrown() throws Exception {
		// as when a class is not available on an older version of Android
		LenientMts7CardFactory failing = new LenientMts7CardFactory() {
			@Override
			public Mts7Card create(Mts7ApduPayloads card) throws UnableToVerifyKeyPairException {
				throw new NoClassDefFoundError("java/util/Base64");
			}
		};

		Mts7WarmupResult result = Mts7Warmup.newBuilder().withLenientFactory(failing).withIterations(5).build().warmUp();

		assertFalse(result.isSuccess());
		assertEquals(1, result.getFailures().size());
		// stops when there is nothing left to warm up
		assertEquals(1, result.getIterations());
	}

	@Test
	public void testNotVerifiedIsReported() throws Exception {
		LenientMts7CardFactory notVerifying = new LenientMts7CardFactory() {
			@Override
			public Mts7Card create(Mts7ApduPayloads card) throws UnableToVerifyKeyPairException {
				return new Mts7Card();
			}
		};

		Mts7WarmupResult result = Mts7Warmup.newBuilder().withLenientFactory(notVerifying).build().warmUp();

		assertFalse(result.isSuccess());
		assertTrue(result.getFailures().get(0).getCause().getMessage().contains("not verified"), result.getFailures().get(0).getCause().getMessage());
	}

	@Test
	public void testInterruptedStopsAfterTheCurrentIteration() throws Exception {
		Thread.currentThread().interrupt();
		try {
			Mts7WarmupResult result = allFactories().withIterations(1000).build().warmUp();

			assertTrue(result.isSuccess(), result.getFailures().toString());
			assertEquals(1, result.getIterations());
		} finally {
			// leave the thread as it was
			assertTrue(Thread.interrupted());
		}
	}

	@Test
	public void testRunnable() throws Exception {
		allFactories().withIterations(2).build().run();

		LenientMts7CardFactory failing = new LenientMts7CardFactory() {
			@Override
			public Mts7Card create(Mts7ApduPayloads card) throws UnableToVerifyKeyPairException {
				throw new IllegalArgumentException("Broken");
			}
		};
		// does not throw
		Mts7Warmup.newBuilder().withLenientFactory(failing).build().run();
	}

	@Test
	public void testInstanceCanBeUsedMoreThanOnce() throws Exception {
		Mts7Warmup warmup = allFactories().withIterations(2).build();

		assertEquals(2, warmup.warmUp().getIterations());
		assertEquals(2, warmup.warmUp().getIterations());
	}

	@Test
	public void testProviderOfTheFactory() {
		assertNull(new IccPublicKeyFactory().getProvider());

		Provider provider = java.security.Security.getProviders()[0];
		assertSame(provider, new IccPublicKeyFactory(provider).getProvider());
		assertNotNull(provider);
	}

	/**
	 * Counts the keys which are created.
	 */

	private static class CountingKeyFactory extends IssuerSignatureFactory {

		private final AtomicInteger calls = new AtomicInteger();

		CountingKeyFactory() throws Exception {
			super();
		}

		@Override
		public IssuerPublicKey createIssuerPublicKey(long pid, JwkPublic jwkPublic) throws UnableToConstructIssuerKeyException {
			calls.incrementAndGet();
			return super.createIssuerPublicKey(pid, jwkPublic);
		}
	}

	/**
	 * Factory which does not support the type of key, i.e. returns null.
	 */

	private static class UnsupportedKeyFactory extends IssuerSignatureFactory {

		private int calls;

		UnsupportedKeyFactory() throws Exception {
			super();
		}

		@Override
		public IssuerPublicKey createIssuerPublicKey(long pid, JwkPublic jwkPublic) {
			calls++;
			return null;
		}
	}

	private static class CountingEnricher extends Mts7CardEnricher {

		private final AtomicInteger calls = new AtomicInteger();

		@Override
		public void enrichSelectApplicationResponsePayload(Mts7Card card, byte[] selectApplicationResponsePayload) {
			calls.incrementAndGet();
			super.enrichSelectApplicationResponsePayload(card, selectApplicationResponsePayload);
		}
	}

	private static ParticipantPublicKeys keysWith(IssuerSignatureFactory factory, List<ParticipantMetadata> participants) {
		Map<Long, ParticipantPublicKeys.Issuer> issuers = new HashMap<>();
		for (ParticipantMetadata p : participants) {
			Map<String, ParticipantPublicKeys.IssuerKey> keys = new HashMap<>();
			for (JwkPublic jwk : p.getMtbPublicKeys()) {
				keys.put(jwk.getKid(), new ParticipantPublicKeys.IssuerKey(jwk));
			}
			issuers.put(p.getPid(), new ParticipantPublicKeys.Issuer(p.getOrganisationName(), p.getPid(), keys, factory));
		}
		return new ParticipantPublicKeys(issuers);
	}

	private static int countKeys(List<ParticipantMetadata> participants, Long... participantIds) {
		List<Long> ids = Arrays.asList(participantIds);

		int count = 0;
		for (ParticipantMetadata p : participants) {
			if (ids.isEmpty() || ids.contains(p.getPid())) {
				count += p.getMtbPublicKeys().size();
			}
		}
		return count;
	}

	@Test
	public void testIssuerKeysAreCreatedInAdvance() throws Exception {
		List<ParticipantMetadata> participants = readParticipantMetadata();

		CountingKeyFactory factory = new CountingKeyFactory();
		ParticipantPublicKeys keys = keysWith(factory, participants);
		assertEquals(0, factory.calls.get());

		Mts7Warmup warmup = Mts7Warmup.newBuilder().withParticipantPublicKeys(keys).build();

		Mts7WarmupResult result = warmup.warmUp();
		assertTrue(result.isSuccess(), result.getFailures().toString());

		int total = countKeys(participants);
		assertTrue(total > 100, "Keys: " + total);
		assertEquals(total, factory.calls.get());

		// so no more work for the first card
		for (ParticipantMetadata p : participants) {
			for (JwkPublic jwk : p.getMtbPublicKeys()) {
				assertNotNull(keys.getIssuerPublicKey(p.getPid(), jwk.getKid()));
			}
		}
		assertEquals(total, factory.calls.get());

		// and warming up again is harmless
		assertTrue(warmup.warmUp().isSuccess());
		assertEquals(total, factory.calls.get());
	}

	@Test
	public void testIssuerKeysOfSomeParticipants() throws Exception {
		List<ParticipantMetadata> participants = readParticipantMetadata();

		CountingKeyFactory factory = new CountingKeyFactory();
		ParticipantPublicKeys keys = keysWith(factory, participants);

		// unknown participants are ignored
		Mts7WarmupResult result = Mts7Warmup.newBuilder().withParticipantPublicKeys(keys, Arrays.asList(10L, 11L, -1L, 12345L)).build().warmUp();
		assertTrue(result.isSuccess(), result.getFailures().toString());

		int expected = countKeys(participants, 10L, 11L);
		assertTrue(expected > 0 && expected < countKeys(participants));
		assertEquals(expected, factory.calls.get());

		// the others are still created when they are used
		assertNotNull(keys.getIssuerPublicKey(10, "10:20230213"));
		assertEquals(expected, factory.calls.get());

		// an empty list is nobody
		CountingKeyFactory nobody = new CountingKeyFactory();
		assertTrue(Mts7Warmup.newBuilder().withParticipantPublicKeys(keysWith(nobody, participants), new ArrayList<Long>()).build().warmUp().isSuccess());
		assertEquals(0, nobody.calls.get());
	}

	@Test
	public void testUnsupportedKeyIsReported() throws Exception {
		UnsupportedKeyFactory factory = new UnsupportedKeyFactory();

		Map<String, ParticipantPublicKeys.IssuerKey> keys = new HashMap<>();
		keys.put("99:unsupported", new ParticipantPublicKeys.IssuerKey(new JwkPublic().kty("EC").kid("99:unsupported")));

		Map<Long, ParticipantPublicKeys.Issuer> issuers = new HashMap<>();
		issuers.put(99L, new ParticipantPublicKeys.Issuer("Unsupported", 99L, keys, factory));

		ParticipantPublicKeys participantPublicKeys = new ParticipantPublicKeys(issuers);

		Mts7WarmupResult result = Mts7Warmup.newBuilder().withParticipantPublicKeys(participantPublicKeys).build().warmUp();

		assertEquals(1, result.getFailures().size(), "warm-up must not report success for a key which was not created");
		assertTrue(result.getFailures().get(0).getMessage().contains("99:unsupported"), result.getFailures().get(0).getMessage());

		// the answer is remembered, so that it does not have to be worked out again for every card
		assertNull(participantPublicKeys.getIssuerPublicKey(99, "99:unsupported"));
		assertEquals(1, factory.calls);
	}

	@Test
	public void testTheFactoriesWhichAreGivenAreTheOnesWhichAreWarmedUp() throws Exception {
		CountingEnricher enricher = new CountingEnricher();

		VerifyMts7CardFactory factory = new VerifyMts7CardFactory(ParticipantPublicKeys.newBuilder().build(), new IccPublicKeyFactory(), enricher,
				new CBORMapper(), new ThumbprintFactory(null));

		Mts7WarmupResult result = Mts7Warmup.newBuilder().withVerifyFactory(factory).withIterations(4).build().warmUp();

		assertTrue(result.isSuccess(), result.getFailures().toString());
		assertEquals(4, result.getIterations());
		// the helper of the factory, not one of our own
		assertEquals(4, enricher.calls.get());
	}

	@Test
	public void testHelpers() throws Exception {
		CountingEnricher enricher = new CountingEnricher();

		// as for the factories which are not part of this module
		Mts7WarmupResult result = Mts7Warmup.newBuilder()
				.withHelpers(new IccPublicKeyFactory(), enricher, new CBORMapper(), new ThumbprintFactory(null))
				.withIterations(4)
				.build()
				.warmUp();

		assertTrue(result.isSuccess(), result.getFailures().toString());
		assertEquals(4, result.getIterations());
		assertEquals(4, enricher.calls.get());
	}

	@Test
	public void testHelpersMustBeGiven() throws Exception {
		IccPublicKeyFactory icc = new IccPublicKeyFactory();
		Mts7CardEnricher enricher = new Mts7CardEnricher();
		CBORMapper mapper = new CBORMapper();
		ThumbprintFactory thumbprints = new ThumbprintFactory(null);

		assertThrows(NullPointerException.class, () -> Mts7Warmup.newBuilder().withHelpers(null, enricher, mapper, thumbprints));
		assertThrows(NullPointerException.class, () -> Mts7Warmup.newBuilder().withHelpers(icc, null, mapper, thumbprints));
		assertThrows(NullPointerException.class, () -> Mts7Warmup.newBuilder().withHelpers(icc, enricher, null, thumbprints));
		assertThrows(NullPointerException.class, () -> Mts7Warmup.newBuilder().withHelpers(icc, enricher, mapper, null));
	}

}
