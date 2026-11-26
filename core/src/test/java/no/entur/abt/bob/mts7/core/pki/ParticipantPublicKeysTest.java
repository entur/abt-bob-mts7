package no.entur.abt.bob.mts7.core.pki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import no.entur.abt.bob.api.pm.model.MtbJwkPublic;
import no.entur.abt.bob.api.pm.model.ParticipantMetadata;
import no.entur.abt.bob.mts7.core.UnableToConstructIssuerKeyException;

public class ParticipantPublicKeysTest {

	@Test
	public void parseMetadataWithSignatureConstraintAndAuthtokenKeys() throws Exception {
		ParticipantMetadata[] parsed;
		try (InputStream is = getClass().getResourceAsStream("/participantMetadataSignatureConstraint.json")) {
			parsed = new ObjectMapper().readValue(is, ParticipantMetadata[].class);
		}

		assertEquals(MtbJwkPublic.BobScEnum.TICKET, parsed[0].getMtbPublicKeys().get(0).getBobSc());
		assertEquals(1, parsed[0].getAuthtokenPublicKeys().size());

		ParticipantPublicKeys keys = ParticipantPublicKeys.newBuilder().withParticipants(Arrays.asList(parsed)).build();
		assertNotNull(keys);
	}

	@Test
	public void parseRootCertififcates() throws Exception {
		ObjectMapper mapper = new ObjectMapper();

		InputStream is = getClass().getResourceAsStream("/participantMetadata.json");

		List<ParticipantMetadata> participantMetadata = Arrays.asList(mapper.readValue(is, ParticipantMetadata[].class));
		assertFalse(participantMetadata.isEmpty());

		ParticipantPublicKeys participantPublicKeys = ParticipantPublicKeys.newBuilder().withParticipants(participantMetadata).build();

		for (ParticipantMetadata p : participantMetadata) {
			List<MtbJwkPublic> mtbPublicKeys = p.getMtbPublicKeys();

			for (MtbJwkPublic key : mtbPublicKeys) {
				IssuerPublicKey issuerPublicKey = participantPublicKeys.getIssuerPublicKey(p.getPid(), key.getKid());

				assertNotNull(issuerPublicKey);
			}
		}

	}

	private List<ParticipantMetadata> readParticipantMetadata() throws Exception {
		InputStream is = getClass().getResourceAsStream("/participantMetadata.json");

		List<ParticipantMetadata> participantMetadata = Arrays.asList(new ObjectMapper().readValue(is, ParticipantMetadata[].class));
		assertFalse(participantMetadata.isEmpty());

		return participantMetadata;
	}

	@Test
	public void testKeyIsCreatedOnce() throws Exception {
		ParticipantPublicKeys participantPublicKeys = ParticipantPublicKeys.newBuilder().withParticipants(readParticipantMetadata()).build();

		// the same key is returned, so that it is reused
		assertSame(participantPublicKeys.getIssuerPublicKey(10, "10:20230213"), participantPublicKeys.getIssuerPublicKey(10, "10:20230213"));
		assertNotSame(participantPublicKeys.getIssuerPublicKey(10, "10:20230213"), participantPublicKeys.getIssuerPublicKey(10, "LjoSsfxuTA"));
	}

	@Test
	public void testUnknownKeys() throws Exception {
		ParticipantPublicKeys participantPublicKeys = ParticipantPublicKeys.newBuilder().withParticipants(readParticipantMetadata()).build();

		assertEquals(null, participantPublicKeys.getIssuerPublicKey(10, "unknown"));
		assertEquals(null, participantPublicKeys.getIssuerPublicKey(-1, "10:20230213"));
	}

	@Test
	public void testInvalidKeyIsReportedEveryTimeItIsUsed() throws Exception {
		List<ParticipantMetadata> participantMetadata = new ArrayList<>(readParticipantMetadata());

		// not a point on the curve
		MtbJwkPublic invalid = new MtbJwkPublic().kty("EC").kid("99:invalid").crv("P-256").x("AAAA").y("AAAA");
		participantMetadata.add(new ParticipantMetadata().pid(99L).organisationName("Invalid").addMtbPublicKeysItem(invalid));

		ParticipantPublicKeys participantPublicKeys = ParticipantPublicKeys.newBuilder().withParticipants(participantMetadata).build();

		// the other keys are fine
		assertNotNull(participantPublicKeys.getIssuerPublicKey(10, "10:20230213"));

		assertThrows(UnableToConstructIssuerKeyException.class, () -> participantPublicKeys.getIssuerPublicKey(99, "99:invalid"));
		assertThrows(UnableToConstructIssuerKeyException.class, () -> participantPublicKeys.getIssuerPublicKey(99, "99:invalid"));
	}

	@Test
	public void testParticipantsAndKeys() throws Exception {
		List<ParticipantMetadata> participantMetadata = readParticipantMetadata();

		ParticipantPublicKeys participantPublicKeys = ParticipantPublicKeys.newBuilder().withParticipants(participantMetadata).build();

		Set<Long> participantIds = participantPublicKeys.getParticipantIds();
		assertEquals(participantMetadata.size(), participantIds.size());
		assertTrue(participantIds.contains(10L));

		ParticipantPublicKeys.Issuer issuer = participantPublicKeys.getIssuer(10);
		assertEquals("Sk\u00e5netrafiken", issuer.getName());
		assertTrue(issuer.getKeyIds().contains("10:20230213"));
		assertTrue(issuer.getKeyIds().contains("LjoSsfxuTA"));

		assertNull(participantPublicKeys.getIssuer(-1));

		// copies
		participantIds.clear();
		issuer.getKeyIds().clear();

		assertFalse(participantPublicKeys.getParticipantIds().isEmpty());
		assertFalse(participantPublicKeys.getIssuer(10).getKeyIds().isEmpty());
	}

	/**
	 * Factory which does not support the type of key, i.e. returns null.
	 */

	private static class UnsupportedKeyFactory extends IssuerSignatureFactory {

		int calls;

		UnsupportedKeyFactory() throws Exception {
			super();
		}

		@Override
		public IssuerPublicKey createIssuerPublicKey(long pid, MtbJwkPublic jwkPublic) {
			calls++;
			return null;
		}
	}

	@Test
	public void testUnsupportedKeyIsRemembered() throws Exception {
		UnsupportedKeyFactory factory = new UnsupportedKeyFactory();

		Map<String, ParticipantPublicKeys.IssuerKey> keys = new HashMap<>();
		keys.put("99:unsupported", new ParticipantPublicKeys.IssuerKey(new MtbJwkPublic().kty("EC").kid("99:unsupported")));

		Map<Long, ParticipantPublicKeys.Issuer> issuers = new HashMap<>();
		issuers.put(99L, new ParticipantPublicKeys.Issuer("Unsupported", 99L, keys, factory));

		ParticipantPublicKeys participantPublicKeys = new ParticipantPublicKeys(issuers);

		// no key, which is as for unknown keys
		assertEquals(null, participantPublicKeys.getIssuerPublicKey(99, "99:unsupported"));
		assertEquals(null, participantPublicKeys.getIssuerPublicKey(99, "99:unsupported"));

		// and the answer is remembered, so that it does not have to be worked out again for every card
		assertEquals(1, factory.calls);
	}

	/**
	 * Factory which counts the keys it creates.
	 */

	private static class CountingKeyFactory extends IssuerSignatureFactory {

		final AtomicInteger calls = new AtomicInteger();

		CountingKeyFactory() throws Exception {
			super();
		}

		@Override
		public IssuerPublicKey createIssuerPublicKey(long pid, MtbJwkPublic jwkPublic) throws UnableToConstructIssuerKeyException {
			calls.incrementAndGet();
			return super.createIssuerPublicKey(pid, jwkPublic);
		}
	}

	private static ParticipantPublicKeys participantPublicKeys(List<ParticipantMetadata> participants, IssuerSignatureFactory factory) {
		Map<Long, ParticipantPublicKeys.Issuer> issuers = new HashMap<>();
		for (ParticipantMetadata participant : participants) {
			Map<String, ParticipantPublicKeys.IssuerKey> keys = new HashMap<>();
			for (MtbJwkPublic jwk : participant.getMtbPublicKeys()) {
				keys.put(jwk.getKid(), new ParticipantPublicKeys.IssuerKey(jwk));
			}
			issuers.put(participant.getPid(), new ParticipantPublicKeys.Issuer(participant.getOrganisationName(), participant.getPid(), keys, factory));
		}
		return new ParticipantPublicKeys(issuers);
	}

	@Test
	public void testCreateIssuerPublicKeys() throws Exception {
		List<ParticipantMetadata> participantMetadata = readParticipantMetadata();
		int keys = participantMetadata.stream().mapToInt(participant -> participant.getMtbPublicKeys().size()).sum();

		CountingKeyFactory factory = new CountingKeyFactory();
		ParticipantPublicKeys participantPublicKeys = participantPublicKeys(participantMetadata, factory);

		assertEquals(0, participantPublicKeys.createKeys());
		assertEquals(keys, factory.calls.get());

		// all of the keys were created, so none is created when it is used
		for (ParticipantPublicKeys.Issuer issuer : participantPublicKeys.getIssuers()) {
			for (String kid : issuer.getKeyIds()) {
				assertNotNull(participantPublicKeys.getIssuerPublicKey(issuer.getPid(), kid));
			}
			assertEquals(List.of(), issuer.getUnsupportedKeys());
		}
		assertEquals(keys, factory.calls.get());

		// and not again
		assertEquals(0, participantPublicKeys.createKeys());
		assertEquals(keys, factory.calls.get());
	}

	@Test
	public void testIssuers() throws Exception {
		List<ParticipantMetadata> participantMetadata = readParticipantMetadata();
		ParticipantPublicKeys participantPublicKeys = ParticipantPublicKeys.newBuilder().withParticipants(participantMetadata).build();

		List<ParticipantPublicKeys.Issuer> issuers = participantPublicKeys.getIssuers();

		assertEquals(participantMetadata.size(), issuers.size());
		for (int i = 1; i < issuers.size(); i++) {
			assertTrue(issuers.get(i - 1).getPid() < issuers.get(i).getPid(), "ordered by participant id");
		}
		for (ParticipantPublicKeys.Issuer issuer : issuers) {
			assertSame(issuer, participantPublicKeys.getIssuer(issuer.getPid()));
		}

		// a copy
		issuers.clear();
		assertEquals(participantMetadata.size(), participantPublicKeys.getIssuers().size());
	}

	@Test
	public void testUnsupportedKeys() throws Exception {
		Map<String, ParticipantPublicKeys.IssuerKey> keys = new HashMap<>();
		keys.put("99:unsupported", new ParticipantPublicKeys.IssuerKey(new MtbJwkPublic().kty("EC").kid("99:unsupported")));
		keys.put("99:also unsupported", new ParticipantPublicKeys.IssuerKey(new MtbJwkPublic().kty("EC").kid("99:also unsupported")));

		Map<Long, ParticipantPublicKeys.Issuer> issuers = new HashMap<>();
		issuers.put(99L, new ParticipantPublicKeys.Issuer("Unsupported", 99L, keys, new UnsupportedKeyFactory()));
		ParticipantPublicKeys participantPublicKeys = new ParticipantPublicKeys(issuers);

		ParticipantPublicKeys.Issuer issuer = participantPublicKeys.getIssuer(99);

		// not known until the keys are created
		assertEquals(List.of(), issuer.getUnsupportedKeys());

		// both are invalid
		assertEquals(2, participantPublicKeys.createKeys());

		List<String> unsupported = new ArrayList<>();
		for (ParticipantPublicKeys.IssuerKey key : issuer.getUnsupportedKeys()) {
			unsupported.add(key.getKeyId());
		}
		assertEquals(List.of("99:also unsupported", "99:unsupported"), unsupported);
	}

	@Test
	public void testKeysWhichCannotBeCreated() throws Exception {
		List<ParticipantMetadata> participantMetadata = new ArrayList<>(readParticipantMetadata());

		// not a point on the curve
		MtbJwkPublic invalid = new MtbJwkPublic().kty("EC").kid("99:invalid").crv("P-256").x("AAAA").y("AAAA");
		participantMetadata.add(new ParticipantMetadata().pid(99L).organisationName("Invalid").addMtbPublicKeysItem(invalid));

		ParticipantPublicKeys participantPublicKeys = ParticipantPublicKeys.newBuilder().withParticipants(participantMetadata).build();

		assertEquals(1, participantPublicKeys.createKeys());

		// which one
		List<UnableToConstructIssuerKeyException> failures = participantPublicKeys.getIssuer(99).createKeys();
		assertEquals(1, failures.size());
		assertEquals("Unable to create key 99:invalid for participant 99", failures.get(0).getMessage());
		assertTrue(failures.get(0).getCause() instanceof UnableToConstructIssuerKeyException);
		// a key which cannot be created is not a key whose type is not supported
		assertEquals(List.of(), participantPublicKeys.getIssuer(99).getUnsupportedKeys());
	}

	/**
	 * Factory which cannot create any key, as for key material which is not valid.
	 */

	private static class FailingKeyFactory extends IssuerSignatureFactory {

		final AtomicInteger calls = new AtomicInteger();

		FailingKeyFactory() throws Exception {
			super();
		}

		@Override
		public IssuerPublicKey createIssuerPublicKey(long pid, MtbJwkPublic jwkPublic) throws UnableToConstructIssuerKeyException {
			calls.incrementAndGet();
			throw new UnableToConstructIssuerKeyException("Broken");
		}
	}

	@Test
	public void testFailureIsRemembered() throws Exception {
		FailingKeyFactory factory = new FailingKeyFactory();

		Map<String, ParticipantPublicKeys.IssuerKey> keys = new HashMap<>();
		keys.put("99:broken", new ParticipantPublicKeys.IssuerKey(new MtbJwkPublic().kty("EC").kid("99:broken")));
		Map<Long, ParticipantPublicKeys.Issuer> issuers = new HashMap<>();
		issuers.put(99L, new ParticipantPublicKeys.Issuer("Broken", 99L, keys, factory));
		ParticipantPublicKeys participantPublicKeys = new ParticipantPublicKeys(issuers);

		UnableToConstructIssuerKeyException first = assertThrows(UnableToConstructIssuerKeyException.class,
				() -> participantPublicKeys.getIssuerPublicKey(99, "99:broken"));
		UnableToConstructIssuerKeyException second = assertThrows(UnableToConstructIssuerKeyException.class,
				() -> participantPublicKeys.getIssuerPublicKey(99, "99:broken"));

		// tried once, and reported every time, with the same cause
		assertEquals(1, factory.calls.get());
		assertNotSame(first, second);
		assertSame(first.getCause(), second.getCause());
		assertEquals("Unable to create key 99:broken for participant 99", first.getMessage());
		assertEquals("Broken", first.getCause().getMessage());
		assertTrue(keys.get("99:broken").hasFailure());

		// invalid, but not a key whose type is not supported
		assertEquals(1, participantPublicKeys.createKeys());
		assertEquals(1, factory.calls.get());
		assertEquals(List.of(), participantPublicKeys.getIssuer(99).getUnsupportedKeys());
	}

}
