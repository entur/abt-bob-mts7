package no.entur.abt.bob.mts7.core.pki.jws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.JWKSet;

import no.entur.abt.bob.mts7.core.exception.UnableToVerifyParticipantMetadataException;

public class VerifiedParticipantMetadataFactoryTest {

	private static final long VALID = Instant.parse("2026-11-20T00:00:00Z").toEpochMilli();

	private final VerifiedParticipantMetadataFactory factory;
	private final String jws;

	public VerifiedParticipantMetadataFactoryTest() throws Exception {
		jws = read("/participantMetadataJws.json");
		factory = new VerifiedParticipantMetadataFactory(new ParticipantMetadataJwsParser(),
				new ParticipantMetadataJwsVerifier(JWKSet.parse(read("/samtrafiken-prod.json"))));
	}

	@Test
	public void createVerified() throws Exception {
		VerifiedParticipantMetadata verified = factory.create(jws, VALID);

		assertFalse(verified.getParticipantMetadata().isEmpty());
		assertEquals(10, verified.getParticipantMetadata().get(0).getPid());
		assertEquals(2, verified.getVerifiedHeaders().size());
		assertEquals(2, verified.getJws().getSignatures().size());
	}

	@Test
	public void parseStoredPayloadWithoutJws() throws Exception {
		VerifiedParticipantMetadata verified = factory.create(jws, VALID);
		byte[] payload = verified.getJws().getPayload().toBytes();

		assertEquals(verified.getParticipantMetadata().size(), new ParticipantMetadataJwsParser().parseParticipantMetadata(payload).size());
		assertThrows(UnableToVerifyParticipantMetadataException.class,
				() -> new ParticipantMetadataJwsParser().parseParticipantMetadata("nope".getBytes(StandardCharsets.UTF_8)));
	}

	@Test
	public void rejectGarbage() {
		assertThrows(UnableToVerifyParticipantMetadataException.class, () -> factory.create("not json", VALID));
	}

	@Test
	public void rejectNotVerified() {
		long expired = Instant.parse("2026-11-26T00:00:00Z").toEpochMilli();

		assertThrows(UnableToVerifyParticipantMetadataException.class, () -> factory.create(jws, expired));
	}

	private String read(String resource) throws Exception {
		try (InputStream is = getClass().getResourceAsStream(resource)) {
			return new String(com.nimbusds.jose.util.IOUtils.readInputStreamToString(is, StandardCharsets.UTF_8));
		}
	}

}
