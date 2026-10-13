package no.entur.abt.bob.mts7.core.pki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import no.entur.abt.bob.api.pm.model.JwkPublic;
import no.entur.abt.bob.api.pm.model.ParticipantMetadata;
import no.entur.abt.bob.mts7.core.UnableToConstructIssuerKeyException;

public class ParticipantPublicKeysTest {

	@Test
	public void parseRootCertififcates() throws Exception {
		ObjectMapper mapper = new ObjectMapper();

		InputStream is = getClass().getResourceAsStream("/participantMetadata.json");

		List<ParticipantMetadata> participantMetadata = Arrays.asList(mapper.readValue(is, ParticipantMetadata[].class));
		assertFalse(participantMetadata.isEmpty());

		ParticipantPublicKeys participantPublicKeys = ParticipantPublicKeys.newBuilder().withParticipants(participantMetadata).build();

		for (ParticipantMetadata p : participantMetadata) {
			List<JwkPublic> mtbPublicKeys = p.getMtbPublicKeys();

			for (JwkPublic key : mtbPublicKeys) {
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
	public void testWarmUp() throws Exception {
		List<ParticipantMetadata> participantMetadata = readParticipantMetadata();

		ParticipantPublicKeys participantPublicKeys = ParticipantPublicKeys.newBuilder().withParticipants(participantMetadata).build();

		assertTrue(participantPublicKeys.warmUp().isEmpty());

		// keys are now created, so no more work for the first card
		for (ParticipantMetadata p : participantMetadata) {
			for (JwkPublic key : p.getMtbPublicKeys()) {
				assertSame(participantPublicKeys.getIssuerPublicKey(p.getPid(), key.getKid()), participantPublicKeys.getIssuerPublicKey(p.getPid(), key.getKid()));
			}
		}

		// and warming up again is harmless
		assertTrue(participantPublicKeys.warmUp().isEmpty());
	}

	@Test
	public void testInvalidKeyIsReportedByWarmUpNotThrown() throws Exception {
		List<ParticipantMetadata> participantMetadata = new ArrayList<>(readParticipantMetadata());

		// not a point on the curve
		JwkPublic invalid = new JwkPublic().kty("EC").kid("99:invalid").crv("P-256").x("AAAA").y("AAAA");
		participantMetadata.add(new ParticipantMetadata().pid(99L).organisationName("Invalid").addMtbPublicKeysItem(invalid));

		ParticipantPublicKeys participantPublicKeys = ParticipantPublicKeys.newBuilder().withParticipants(participantMetadata).build();

		List<UnableToConstructIssuerKeyException> failures = participantPublicKeys.warmUp();
		assertEquals(1, failures.size());
		assertTrue(failures.get(0).getMessage().contains("99:invalid"), failures.get(0).getMessage());

		// the other keys are fine
		assertNotNull(participantPublicKeys.getIssuerPublicKey(10, "10:20230213"));

		// and using the key reports the problem (every time)
		assertThrows(UnableToConstructIssuerKeyException.class, () -> participantPublicKeys.getIssuerPublicKey(99, "99:invalid"));
		assertThrows(UnableToConstructIssuerKeyException.class, () -> participantPublicKeys.getIssuerPublicKey(99, "99:invalid"));
	}

	@Test
	public void testWarmUpSomeParticipants() throws Exception {
		List<ParticipantMetadata> participantMetadata = new ArrayList<>(readParticipantMetadata());

		// not a point on the curve
		JwkPublic invalid = new JwkPublic().kty("EC").kid("99:invalid").crv("P-256").x("AAAA").y("AAAA");
		participantMetadata.add(new ParticipantMetadata().pid(99L).organisationName("Invalid").addMtbPublicKeysItem(invalid));

		ParticipantPublicKeys participantPublicKeys = ParticipantPublicKeys.newBuilder().withParticipants(participantMetadata).build();

		// only the participants in the list are warmed up (the key of participant 99 is not valid)
		assertTrue(participantPublicKeys.warmUp(Arrays.asList(10L, 11L)).isEmpty());
		assertSame(participantPublicKeys.getIssuerPublicKey(10, "10:20230213"), participantPublicKeys.getIssuerPublicKey(10, "10:20230213"));

		List<UnableToConstructIssuerKeyException> failures = participantPublicKeys.warmUp(Arrays.asList(10L, 99L));
		assertEquals(1, failures.size());
		assertTrue(failures.get(0).getMessage().contains("99:invalid"), failures.get(0).getMessage());

		// unknown participants are ignored, as is an empty list
		assertTrue(participantPublicKeys.warmUp(Arrays.asList(-1L, 12345L)).isEmpty());
		assertTrue(participantPublicKeys.warmUp(new ArrayList<Long>()).isEmpty());
	}

}
