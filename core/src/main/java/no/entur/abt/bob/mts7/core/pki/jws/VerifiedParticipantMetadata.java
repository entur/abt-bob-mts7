package no.entur.abt.bob.mts7.core.pki.jws;

import java.util.List;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObjectJSON;

import no.entur.abt.bob.api.pm.model.ParticipantMetadata;

/**
 * Participant metadata of which the signature has been verified.
 */

public class VerifiedParticipantMetadata {

	private final List<ParticipantMetadata> participantMetadata;
	private final JWSObjectJSON jws;
	private final List<JWSHeader> verifiedHeaders;

	public VerifiedParticipantMetadata(List<ParticipantMetadata> participantMetadata, JWSObjectJSON jws, List<JWSHeader> verifiedHeaders) {
		this.participantMetadata = participantMetadata;
		this.jws = jws;
		this.verifiedHeaders = verifiedHeaders;
	}

	public List<ParticipantMetadata> getParticipantMetadata() {
		return participantMetadata;
	}

	public JWSObjectJSON getJws() {
		return jws;
	}

	/**
	 * @return headers of the signatures which were verified, never empty
	 */

	public List<JWSHeader> getVerifiedHeaders() {
		return verifiedHeaders;
	}

}
