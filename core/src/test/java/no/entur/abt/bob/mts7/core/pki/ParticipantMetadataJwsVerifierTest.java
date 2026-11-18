package no.entur.abt.bob.mts7.core.pki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.time.Instant;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObjectJSON;
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
	private static final String FALLBACK_KID = "16:metadata_201701_fallback";

	private final String json = read("/participantMetadataJws.json");
	private final JWKSet keys = parseKeys();

	private JWSObjectJSON jws() throws Exception {
		return JWSObjectJSON.parse(json);
	}

	@Test
	public void verifyBothSignatures() throws Exception {
		JWSObjectJSON jws = jws();

		List<JWSHeader> verified = new ParticipantMetadataJwsVerifier(keys).verify(jws, VALID);

		assertEquals(Arrays.asList(ES256_KID, FALLBACK_KID), verified.stream().map(JWSHeader::getKeyID).collect(Collectors.toList()));

		byte[] payload = jws.getPayload().toBytes();
		assertEquals(10, new ObjectMapper().readValue(payload, ParticipantMetadata[].class)[0].getPid());
	}

	@Test
	public void verifyWithFallbackKeyOnly() throws Exception {
		JWKSet fallbackOnly = new JWKSet(keys.getKeyByKeyId(FALLBACK_KID));

		List<JWSHeader> verified = new ParticipantMetadataJwsVerifier(fallbackOnly).verify(jws(), VALID);

		assertEquals(1, verified.size());
		assertEquals(FALLBACK_KID, verified.get(0).getKeyID());
	}

	@Test
	public void rejectUnknownKey() throws Exception {
		JWSObjectJSON jws = jws();

		assertThrows(UnableToVerifyParticipantMetadataException.class, () -> new ParticipantMetadataJwsVerifier(new JWKSet()).verify(jws, VALID));
	}

	@Test
	public void rejectOtherKeyWithSameKid() throws Exception {
		// the fallback key is not trusted, so only the primary signature is considered
		ECKey other = new ECKeyGenerator(Curve.P_256).keyID(ES256_KID).generate().toPublicJWK();
		JWSObjectJSON jws = jws();

		assertThrows(UnableToVerifyParticipantMetadataException.class, () -> new ParticipantMetadataJwsVerifier(new JWKSet(other)).verify(jws, VALID));
	}

	@Test
	public void rejectTamperedPayload() throws Exception {
		JWSObjectJSON tampered = JWSObjectJSON.parse(json.replaceFirst("\"payload\": \"W3si", "\"payload\": \"W3tp"));

		assertThrows(UnableToVerifyParticipantMetadataException.class, () -> new ParticipantMetadataJwsVerifier(keys).verify(tampered, VALID));
	}

	@Test
	public void rejectExpired() throws Exception {
		long after = Instant.parse("2026-11-26T00:00:00Z").toEpochMilli();
		JWSObjectJSON jws = jws();

		assertThrows(UnableToVerifyParticipantMetadataException.class, () -> new ParticipantMetadataJwsVerifier(keys).verify(jws, after));
	}

	@Test
	public void rejectNotYetValid() throws Exception {
		long before = Instant.parse("2026-11-17T00:00:00Z").toEpochMilli();
		JWSObjectJSON jws = jws();

		assertThrows(UnableToVerifyParticipantMetadataException.class, () -> new ParticipantMetadataJwsVerifier(keys).verify(jws, before));
	}

	@Test
	public void acceptExpiredWhenNotCheckingNotValidAfter() throws Exception {
		long after = Instant.parse("2026-11-26T00:00:00Z").toEpochMilli();

		assertEquals(2, new ParticipantMetadataJwsVerifier(keys, true, false).verify(jws(), after).size());
	}

	@Test
	public void acceptNotYetValidWhenNotCheckingNotValidBefore() throws Exception {
		long before = Instant.parse("2026-11-17T00:00:00Z").toEpochMilli();

		assertEquals(2, new ParticipantMetadataJwsVerifier(keys, false, true).verify(jws(), before).size());
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
