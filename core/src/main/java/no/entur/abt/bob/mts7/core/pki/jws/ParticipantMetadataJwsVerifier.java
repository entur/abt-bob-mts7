package no.entur.abt.bob.mts7.core.pki.jws;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObjectJSON;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyConverter;
import com.nimbusds.jose.proc.JWSVerifierFactory;

import no.entur.abt.bob.mts7.core.UnableToVerifyParticipantMetadataException;

/**
 * Verify participant metadata wrapped in a JWS (general JSON serialization).
 * <p>
 * The payload is accepted if at least one of the signatures is valid for a trusted key (selected by <code>kid</code>), and the validity period
 * (<code>notvalidbefore</code> and <code>notvalidafter</code>) of the signature has not passed. Signatures by other keys are ignored, so a primary
 * and a fallback signature can be combined.
 * <p>
 * Instances are thread safe.
 */

public class ParticipantMetadataJwsVerifier {

	private static final Logger LOGGER = LoggerFactory.getLogger(ParticipantMetadataJwsVerifier.class);

	private static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmssX");

	private static final String NOT_VALID_BEFORE = "notvalidbefore";
	private static final String NOT_VALID_AFTER = "notvalidafter";

	private final JWKSet trustedKeys;
	private final boolean checkNotValidBefore;
	private final boolean checkNotValidAfter;
	private final JWSVerifierFactory verifierFactory = new DefaultJWSVerifierFactory();

	/**
	 * Check both <code>notvalidbefore</code> and <code>notvalidafter</code>.
	 *
	 * @param trustedKeys keys used for verifying the signature, for example from <code>samtrafiken-prod.json</code>
	 */

	public ParticipantMetadataJwsVerifier(JWKSet trustedKeys) {
		this(trustedKeys, true, true);
	}

	/**
	 * @param trustedKeys         keys used for verifying the signature, for example from <code>samtrafiken-prod.json</code>
	 * @param checkNotValidBefore check <code>notvalidbefore</code> against the time
	 * @param checkNotValidAfter  check <code>notvalidafter</code> against the time
	 */

	public ParticipantMetadataJwsVerifier(JWKSet trustedKeys, boolean checkNotValidBefore, boolean checkNotValidAfter) {
		this.trustedKeys = trustedKeys;
		this.checkNotValidBefore = checkNotValidBefore;
		this.checkNotValidAfter = checkNotValidAfter;
	}

	/**
	 * Verify the signatures, using the current time for the validity period.
	 *
	 * @param jws JWS in general JSON serialization, with the participant metadata as payload
	 * @return the headers of the signatures which were verified, never empty
	 * @throws UnableToVerifyParticipantMetadataException if no signature could be verified
	 * @see #verify(JWSObjectJSON, long)
	 */

	public List<JWSHeader> verify(JWSObjectJSON jws) throws UnableToVerifyParticipantMetadataException {
		return verify(jws, System.currentTimeMillis());
	}

	/**
	 * Verify the signatures. The payload is not parsed; get it from the JWS after verification.
	 * <p>
	 * Signatures which are not trusted, outside of the validity period or invalid are skipped, and logged at info level.
	 *
	 * @param jws  JWS in general JSON serialization, with the participant metadata as payload
	 * @param time time to check the validity period against, in milliseconds since epoch (for example <code>System.currentTimeMillis()</code>)
	 * @return the headers of the signatures which were verified, never empty
	 * @throws UnableToVerifyParticipantMetadataException if no signature could be verified
	 */

	public List<JWSHeader> verify(JWSObjectJSON jws, long time) throws UnableToVerifyParticipantMetadataException {
		List<JWSHeader> verified = new ArrayList<>();

		for (JWSObjectJSON.Signature signature : jws.getSignatures()) {
			JWSHeader header = signature.getHeader();

			JWK key = header.getKeyID() != null ? trustedKeys.getKeyByKeyId(header.getKeyID()) : null;
			if (key == null) {
				LOGGER.info("No trusted key for kid {}", header.getKeyID());
				continue;
			}

			try {
				checkValidityPeriod(header, time);

				List<java.security.Key> javaKeys = KeyConverter.toJavaKeys(Collections.singletonList(key));
				if (javaKeys.isEmpty()) {
					LOGGER.info("Unsupported trusted key for kid {}", header.getKeyID());
					continue;
				}
				JWSVerifier verifier = verifierFactory.createJWSVerifier(header, javaKeys.get(0));
				if (!signature.verify(verifier)) {
					LOGGER.info("Invalid signature for kid {}", header.getKeyID());
					continue;
				}
			} catch (JOSEException | UnableToVerifyParticipantMetadataException e) {
				LOGGER.info("Unable to verify signature for kid {}: {}", header.getKeyID(), e.getMessage());
				continue;
			}

			verified.add(header);
		}

		if (verified.isEmpty()) {
			throw new UnableToVerifyParticipantMetadataException("Unable to verify participant metadata, no valid signatures");
		}

		return verified;
	}

	private void checkValidityPeriod(JWSHeader header, long time) throws UnableToVerifyParticipantMetadataException {
		if (checkNotValidBefore) {
			Long notBefore = parse(header, NOT_VALID_BEFORE);
			if (notBefore != null && time < notBefore) {
				throw new UnableToVerifyParticipantMetadataException("Not valid before " + notBefore);
			}
		}
		if (checkNotValidAfter) {
			Long notAfter = parse(header, NOT_VALID_AFTER);
			if (notAfter != null && time > notAfter) {
				throw new UnableToVerifyParticipantMetadataException("Not valid after " + notAfter);
			}
		}
	}

	/**
	 * @return milliseconds since epoch, or null if not present
	 */

	private Long parse(JWSHeader header, String name) throws UnableToVerifyParticipantMetadataException {
		Object value = header.getCustomParam(name);
		if (value == null) {
			return null;
		}
		try {
			return TIMESTAMP.parse(value.toString(), Instant::from).toEpochMilli();
		} catch (Exception e) {
			throw new UnableToVerifyParticipantMetadataException("Unable to parse " + name + " value " + value, e);
		}
	}

}
