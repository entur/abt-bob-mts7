package no.entur.abt.bob.mts7.core.pki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;

import no.entur.abt.bob.api.pm.model.ParticipantMetadata;
import no.entur.abt.bob.mts7.core.UnableToVerifyParticipantMetadataException;

public class ParticipantMetadataJwsVerifierTest {

	// the signatures are valid from 2026-11-18T10:03:02Z until 2026-11-25T10:03:02Z
	private static final long VALID = Instant.parse("2026-11-20T00:00:00Z").toEpochMilli();

	private static final String ES256_KID = "16:metadata_201701";

	private final String jws = read("/participantMetadataJws.json");
	private final JWKSet keys = parseKeys();

	@Test
	public void verifyWithPrimaryKey() throws Exception {
		byte[] payload = new ParticipantMetadataJwsVerifier(keys).verify(jws, VALID, true, true);

		assertEquals(10, new ObjectMapper().readValue(payload, ParticipantMetadata[].class)[0].getPid());
	}

	@Test
	public void verifyWithFallbackKeyOnly() throws Exception {
		JWKSet fallbackOnly = new JWKSet(keys.getKeyByKeyId("16:metadata_201701_fallback"));

		assertTrue(new ParticipantMetadataJwsVerifier(fallbackOnly).verify(jws, VALID, true, true).length > 0);
	}

	@Test
	public void rejectUnknownKey() {
		assertThrows(UnableToVerifyParticipantMetadataException.class, () -> new ParticipantMetadataJwsVerifier(new JWKSet()).verify(jws, VALID, true, true));
	}

	@Test
	public void rejectOtherKeyWithSameKid() throws Exception {
		// only the primary signature is considered, as the fallback key is not trusted
		ECKey other = new ECKeyGenerator(Curve.P_256).keyID(ES256_KID).generate().toPublicJWK();

		assertThrows(UnableToVerifyParticipantMetadataException.class,
				() -> new ParticipantMetadataJwsVerifier(new JWKSet(other)).verify(jws, VALID, true, true));
	}

	@Test
	public void rejectTamperedPayload() {
		String tampered = jws.replaceFirst("\"payload\": \"W3si", "\"payload\": \"W3tp");

		assertThrows(UnableToVerifyParticipantMetadataException.class, () -> new ParticipantMetadataJwsVerifier(keys).verify(tampered, VALID, true, true));
	}

	@Test
	public void rejectExpired() {
		long after = Instant.parse("2026-11-26T00:00:00Z").toEpochMilli();

		assertThrows(UnableToVerifyParticipantMetadataException.class, () -> new ParticipantMetadataJwsVerifier(keys).verify(jws, after, true, true));
	}

	@Test
	public void rejectNotYetValid() {
		long before = Instant.parse("2026-11-17T00:00:00Z").toEpochMilli();

		assertThrows(UnableToVerifyParticipantMetadataException.class, () -> new ParticipantMetadataJwsVerifier(keys).verify(jws, before, true, true));
	}

	@Test
	public void acceptExpiredWhenNotCheckingNotValidAfter() throws Exception {
		long after = Instant.parse("2026-11-26T00:00:00Z").toEpochMilli();

		assertTrue(new ParticipantMetadataJwsVerifier(keys).verify(jws, after, true, false).length > 0);
	}

	@Test
	public void acceptNotYetValidWhenNotCheckingNotValidBefore() throws Exception {
		long before = Instant.parse("2026-11-17T00:00:00Z").toEpochMilli();

		assertTrue(new ParticipantMetadataJwsVerifier(keys).verify(jws, before, false, true).length > 0);
	}

	@Test
	public void rejectGarbage() {
		assertThrows(UnableToVerifyParticipantMetadataException.class, () -> new ParticipantMetadataJwsVerifier(keys).verify("not json", VALID, true, true));
	}

	private JWKSet parseKeys() {
		try {
			return JWKSet.parse(read("/samtrafiken-prod.json"));
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	private String read(String resource) {
		try (InputStream is = getClass().getResourceAsStream(resource)) {
			return new String(com.nimbusds.jose.util.IOUtils.readInputStreamToString(is, StandardCharsets.UTF_8));
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

}
