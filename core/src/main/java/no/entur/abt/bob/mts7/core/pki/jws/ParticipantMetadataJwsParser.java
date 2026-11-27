package no.entur.abt.bob.mts7.core.pki.jws;

import java.util.Arrays;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSObjectJSON;

import no.entur.abt.bob.api.pm.model.ParticipantMetadata;
import no.entur.abt.bob.mts7.core.exception.UnableToVerifyParticipantMetadataException;

/**
 * Parse participant metadata wrapped in a JWS (general JSON serialization). Parsing does not verify anything; see {@linkplain ParticipantMetadataJwsVerifier}.
 * <p>
 * Instances are thread safe.
 */

public class ParticipantMetadataJwsParser {

	private final ObjectMapper mapper = new ObjectMapper();

	/**
	 * @param jws JWS in general JSON serialization
	 * @return the parsed, not verified, JWS
	 * @throws UnableToVerifyParticipantMetadataException if the JWS could not be parsed
	 */

	public JWSObjectJSON parseJws(String jws) throws UnableToVerifyParticipantMetadataException {
		try {
			return JWSObjectJSON.parse(jws);
		} catch (Exception e) {
			throw new UnableToVerifyParticipantMetadataException("Unable to parse JWS", e);
		}
	}

	/**
	 * Parse the payload; only do this for a JWS which has been verified.
	 *
	 * @param jws parsed JWS
	 * @return the participants of the payload
	 * @throws UnableToVerifyParticipantMetadataException if the payload could not be parsed
	 */

	public List<ParticipantMetadata> parseParticipantMetadata(JWSObjectJSON jws) throws UnableToVerifyParticipantMetadataException {
		return parseParticipantMetadata(jws.getPayload().toBytes());
	}

	/**
	 * Parse a payload without a JWS, for example a stored payload which was verified when it was downloaded.
	 *
	 * @param payload the raw payload (a JSON array of participants)
	 * @return the participants of the payload
	 * @throws UnableToVerifyParticipantMetadataException if the payload could not be parsed
	 */

	public List<ParticipantMetadata> parseParticipantMetadata(byte[] payload) throws UnableToVerifyParticipantMetadataException {
		try {
			return Arrays.asList(mapper.readValue(payload, ParticipantMetadata[].class));
		} catch (Exception e) {
			throw new UnableToVerifyParticipantMetadataException("Unable to parse participant metadata", e);
		}
	}

}
