package no.entur.abt.bob.mts7.core.pki.jws;

import java.util.List;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObjectJSON;

import no.entur.abt.bob.api.pm.model.ParticipantMetadata;
import no.entur.abt.bob.mts7.core.UnableToVerifyParticipantMetadataException;

/**
 * Parse and verify participant metadata wrapped in a JWS. The payload is only parsed after the signatures have been verified.
 * <p>
 * Instances are thread safe.
 */

public class VerifiedParticipantMetadataFactory {

	private final ParticipantMetadataJwsParser parser;
	private final ParticipantMetadataJwsVerifier verifier;

	public VerifiedParticipantMetadataFactory(ParticipantMetadataJwsParser parser, ParticipantMetadataJwsVerifier verifier) {
		this.parser = parser;
		this.verifier = verifier;
	}

	/**
	 * Verify using the current time for the validity period.
	 *
	 * @param jws JWS in general JSON serialization
	 * @return verified participant metadata
	 * @throws UnableToVerifyParticipantMetadataException if the JWS or payload could not be parsed, or if no signature could be verified
	 */

	public VerifiedParticipantMetadata create(String jws) throws UnableToVerifyParticipantMetadataException {
		return create(jws, System.currentTimeMillis());
	}

	/**
	 * @param jws  JWS in general JSON serialization
	 * @param time time to check the validity period against, in milliseconds since epoch
	 * @return verified participant metadata
	 * @throws UnableToVerifyParticipantMetadataException if the JWS or payload could not be parsed, or if no signature could be verified
	 */

	public VerifiedParticipantMetadata create(String jws, long time) throws UnableToVerifyParticipantMetadataException {
		JWSObjectJSON parsed = parser.parseJws(jws);

		List<JWSHeader> verifiedHeaders = verifier.verify(parsed, time);

		List<ParticipantMetadata> participantMetadata = parser.parseParticipantMetadata(parsed);

		return new VerifiedParticipantMetadata(participantMetadata, parsed, verifiedHeaders);
	}

}
