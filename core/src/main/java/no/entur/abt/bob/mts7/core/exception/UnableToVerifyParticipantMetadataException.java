package no.entur.abt.bob.mts7.core.exception;

import no.entur.abt.bob.mts7.api.Mts7Exception;

public class UnableToVerifyParticipantMetadataException extends Mts7Exception {

	private static final long serialVersionUID = 1L;

	public UnableToVerifyParticipantMetadataException(String message) {
		super(message);
	}

	public UnableToVerifyParticipantMetadataException(String message, Throwable cause) {
		super(message, cause);
	}

}
