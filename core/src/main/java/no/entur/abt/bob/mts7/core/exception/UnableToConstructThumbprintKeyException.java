package no.entur.abt.bob.mts7.core.exception;

import no.entur.abt.bob.mts7.api.VerifierMts7Exception;

/**
 * The thumbprint of the public key of the card cannot be created, although the key itself is fine, for example because the digest algorithm is not available (a
 * problem with the verifier). A public key of the card which is missing or not valid is a problem on the card side:
 * {@linkplain NonCompliantIccKeyInvalidCardMts7Exception}.
 */

public class UnableToConstructThumbprintKeyException extends VerifierMts7Exception {

	private static final long serialVersionUID = 1L;

	public UnableToConstructThumbprintKeyException() {
		super();
	}

	public UnableToConstructThumbprintKeyException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public UnableToConstructThumbprintKeyException(String message, Throwable cause) {
		super(message, cause);
	}

	public UnableToConstructThumbprintKeyException(String message) {
		super(message);
	}

	public UnableToConstructThumbprintKeyException(Throwable cause) {
		super(cause);
	}

}
