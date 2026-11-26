package no.entur.abt.bob.mts7.core.pki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;

import no.entur.abt.bob.api.pm.model.MtbJwkPublic;
import no.entur.abt.bob.api.pm.model.ParticipantMetadata;
import no.entur.abt.bob.mts7.core.VerifyMts7CardFactory;

public class ParticipantMetadataSourceTest {

	@Test
	public void testUnknownRootKeysAreNeverTrusted() {
		ParticipantMetadataSource source = new ParticipantMetadataSource(null);

		assertFalse(source.getVerifyMts7CardFactory().isTrustUnknownRootKeys());
		assertEquals(Collections.emptySet(), source.getParticipantPublicKeys().getParticipantIds());

		source.update(Arrays.asList(participant(10, "Ten", key("ten:1"))));

		assertFalse(source.getVerifyMts7CardFactory().isTrustUnknownRootKeys());
		assertEquals(Collections.singleton(10L), source.getParticipantPublicKeys().getParticipantIds());
	}

	@Test
	public void testKeysWhichAreNoLongerInTheSetAreRemoved() throws Exception {
		ParticipantMetadataSource source = new ParticipantMetadataSource(null);
		source.update(Arrays.asList(participant(10, "Ten", key("ten:1"))));
		ECKey elevenKey = key("eleven:1");

		source.update(Arrays.asList(participant(11, "Eleven", elevenKey)));

		assertEquals(Collections.singleton(11L), source.getParticipantPublicKeys().getParticipantIds());
		assertNull(source.getParticipantPublicKeys().getIssuerPublicKey(10, "ten:1"));
		assertTrue(verifies(source, 11, elevenKey));
	}

	@Test
	public void testSetWithoutKeysIsRefusedAndTheKeysInUseAreKept() {
		ParticipantMetadataSource source = new ParticipantMetadataSource(null);
		source.update(Arrays.asList(participant(10, "Ten", key("ten:1"))));
		VerifyMts7CardFactory factory = source.getVerifyMts7CardFactory();

		assertThrows(IllegalArgumentException.class, () -> source.update(Arrays.asList(new ParticipantMetadata().pid(11L).organisationName("Eleven"))));
		assertThrows(IllegalArgumentException.class, () -> source.update(Collections.<ParticipantMetadata>emptyList()));

		assertSame(factory, source.getVerifyMts7CardFactory());
		assertEquals(Collections.singleton(10L), source.getParticipantPublicKeys().getParticipantIds());
	}

	@Test
	public void testSetOfKeysWhichCannotBeUsedIsRefused() {
		// garbage does not count as keys
		ParticipantMetadataSource source = new ParticipantMetadataSource(null);
		source.update(Arrays.asList(participant(10, "Ten", key("ten:1"))));
		VerifyMts7CardFactory factory = source.getVerifyMts7CardFactory();

		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
				() -> source.update(Arrays.asList(participant(11, "Eleven", invalidKey("11:1"), invalidKey("11:2")))));

		assertTrue(e.getMessage().contains("0 issuer keys which can be used"), e.getMessage());
		assertSame(factory, source.getVerifyMts7CardFactory());
	}

	@Test
	public void testAFewKeysWhichCannotBeUsedDoNotStopTheUpdate() throws Exception {
		ParticipantMetadataSource source = new ParticipantMetadataSource(null);
		ECKey elevenKey = key("eleven:1");

		source.update(Arrays.asList(participant(11, "Eleven", invalidKey("11:0"), mtbKey(elevenKey))));

		assertEquals(Collections.singleton(11L), source.getParticipantPublicKeys().getParticipantIds());
		assertTrue(verifies(source, 11, elevenKey));
	}

	@Test
	public void testTooFewValidKeysIsRefused() {
		ParticipantMetadataSource source = ParticipantMetadataSource.newBuilder().withMinimumValidKeys(2).withMaximumInvalidKeys(0).build();

		IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> source.update(Arrays.asList(participant(10, "Ten", key("ten:1")))));
		assertTrue(e.getMessage().contains("at least 2"), e.getMessage());

		source.update(Arrays.asList(participant(10, "Ten", key("ten:1"), key("ten:2"))));
		assertEquals(Collections.singleton(10L), source.getParticipantPublicKeys().getParticipantIds());
	}

	@Test
	public void testTooManyInvalidKeysIsRefused() {
		ParticipantMetadataSource source = ParticipantMetadataSource.newBuilder().withMaximumInvalidKeys(1).build();
		source.update(Arrays.asList(participant(10, "Ten", key("ten:1"))));
		VerifyMts7CardFactory factory = source.getVerifyMts7CardFactory();

		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
				() -> source.update(Arrays.asList(participant(11, "Eleven", invalidKey("11:0"), invalidKey("11:1"), mtbKey(key("eleven:1"))))));
		assertTrue(e.getMessage().contains("at most 1"), e.getMessage());
		assertSame(factory, source.getVerifyMts7CardFactory());

		// the maximum is accepted
		source.update(Arrays.asList(participant(11, "Eleven", invalidKey("11:0"), mtbKey(key("eleven:1")))));
		assertEquals(Collections.singleton(11L), source.getParticipantPublicKeys().getParticipantIds());
	}

	@Test
	public void testKeysAreCreatedWhenTheSetIsLoaded() {
		ParticipantMetadataSource source = new ParticipantMetadataSource(null);
		source.update(Arrays.asList(participant(11, "Eleven", invalidKey("11:0"), mtbKey(key("eleven:1")))));

		// already created: the key which cannot be used is known
		ParticipantPublicKeys.Issuer issuer = source.getParticipantPublicKeys().getIssuer(11);
		assertEquals(1, issuer.createKeys().size());
		assertEquals(1, source.getParticipantPublicKeys().createKeys());
	}

	@Test
	public void testUnchangedSetKeepsFactory() {
		ParticipantMetadataSource source = new ParticipantMetadataSource(null);
		ECKey tenKey = key("ten:1");
		source.update(Arrays.asList(participant(10, "Ten", tenKey)));
		VerifyMts7CardFactory factory = source.getVerifyMts7CardFactory();

		// equal, but not the same instances, as when the set is parsed again
		source.update(Arrays.asList(participant(10, "Ten", tenKey)));
		assertSame(factory, source.getVerifyMts7CardFactory());

		source.update(Arrays.asList(participant(10, "Ten", tenKey), participant(11, "Eleven", key("eleven:1"))));
		assertNotSame(factory, source.getVerifyMts7CardFactory());
		assertEquals(new HashSet<>(Arrays.asList(10L, 11L)), source.getParticipantPublicKeys().getParticipantIds());
	}

	@Test
	public void testTooFewParticipantsIsRefused() {
		ParticipantMetadataSource source = ParticipantMetadataSource.newBuilder().withMinimumParticipants(2).build();

		// a participant whose keys cannot be used does not count
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
				() -> source.update(Arrays.asList(participant(10, "Ten", key("ten:1")), participant(11, "Eleven", invalidKey("11:1")))));
		assertTrue(e.getMessage().contains("1 participants with issuer keys which can be used, at least 2"), e.getMessage());

		source.update(Arrays.asList(participant(10, "Ten", key("ten:1")), participant(11, "Eleven", key("eleven:1"))));
		assertEquals(new HashSet<>(Arrays.asList(10L, 11L)), source.getParticipantPublicKeys().getParticipantIds());
	}

	@Test
	public void testRequiredParticipantsMustHaveKeysWhichCanBeUsed() {
		ParticipantMetadataSource source = ParticipantMetadataSource.newBuilder()
				.withRequiredParticipant(10)
				.withRequiredParticipants(Arrays.asList(11L))
				.build();
		source.update(Arrays.asList(participant(10, "Ten", key("ten:1")), participant(11, "Eleven", key("eleven:1"))));
		VerifyMts7CardFactory factory = source.getVerifyMts7CardFactory();

		// missing
		IllegalArgumentException missing = assertThrows(IllegalArgumentException.class,
				() -> source.update(Arrays.asList(participant(10, "Ten", key("ten:1")), participant(12, "Twelve", key("twelve:1")))));
		assertTrue(missing.getMessage().contains("required participants [11]"), missing.getMessage());

		// without keys which can be used
		IllegalArgumentException invalid = assertThrows(IllegalArgumentException.class,
				() -> source.update(Arrays.asList(participant(10, "Ten", invalidKey("10:1")), participant(11, "Eleven", key("eleven:1")))));
		assertTrue(invalid.getMessage().contains("required participants [10]"), invalid.getMessage());

		assertSame(factory, source.getVerifyMts7CardFactory());
	}

	@Test
	public void testLimits() {
		ParticipantMetadataSource source = new ParticipantMetadataSource(null);
		assertEquals(ParticipantMetadataSource.DEFAULT_MINIMUM_VALID_KEYS, source.getMinimumValidKeys());
		assertEquals(ParticipantMetadataSource.DEFAULT_MAXIMUM_INVALID_KEYS, source.getMaximumInvalidKeys());
		assertEquals(ParticipantMetadataSource.DEFAULT_MINIMUM_PARTICIPANTS, source.getMinimumParticipants());
		assertEquals(Collections.emptySet(), source.getRequiredParticipants());

		// a minimum of zero valid keys would accept garbage
		assertThrows(IllegalArgumentException.class, () -> ParticipantMetadataSource.newBuilder().withMinimumValidKeys(0).build());
		assertThrows(IllegalArgumentException.class, () -> ParticipantMetadataSource.newBuilder().withMaximumInvalidKeys(-1).build());
		assertThrows(IllegalArgumentException.class, () -> ParticipantMetadataSource.newBuilder().withMinimumParticipants(0).build());
		assertNotNull(ParticipantMetadataSource.newBuilder().withMaximumInvalidKeys(0).build());
	}

	/**
	 * @return whether the issuer key of the source with the id of the given key verifies a signature made with the given key
	 */

	private static boolean verifies(ParticipantMetadataSource source, long pid, ECKey signer) throws Exception {
		byte[] data = "issuer signed data".getBytes(StandardCharsets.UTF_8);
		byte[] signature = new ECDSASigner(signer).sign(new JWSHeader(JWSAlgorithm.ES256), data).decode();
		IssuerPublicKey issuerPublicKey = source.getParticipantPublicKeys().getIssuerPublicKey(pid, signer.getKeyID());
		return issuerPublicKey.verify(data, signature);
	}

	private static ParticipantMetadata participant(long pid, String name, ECKey... keys) {
		return participant(pid, name, Arrays.stream(keys).map(ParticipantMetadataSourceTest::mtbKey).toArray(MtbJwkPublic[]::new));
	}

	private static ParticipantMetadata participant(long pid, String name, MtbJwkPublic... keys) {
		List<MtbJwkPublic> list = Arrays.stream(keys).collect(Collectors.toList());
		return new ParticipantMetadata().pid(pid).organisationName(name).mtbPublicKeys(list);
	}

	private static MtbJwkPublic mtbKey(ECKey key) {
		return new MtbJwkPublic().kty("EC").kid(key.getKeyID()).crv("P-256").x(key.getX().toString()).y(key.getY().toString());
	}

	// not a point on the curve
	private static MtbJwkPublic invalidKey(String kid) {
		return new MtbJwkPublic().kty("EC").kid(kid).crv("P-256").x("AAAA").y("AAAA");
	}

	private static ECKey key(String kid) {
		try {
			return new ECKeyGenerator(Curve.P_256).keyID(kid).generate();
		} catch (JOSEException e) {
			throw new IllegalStateException(e);
		}
	}

}
