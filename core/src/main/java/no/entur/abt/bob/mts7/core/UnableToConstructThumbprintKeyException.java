package no.entur.abt.bob.mts7.core;

/**
 * The thumbprint of the public key of the card cannot be created, although the key itself is fine, for example because the digest algorithm is not available (a
 * problem on our side). A public key of the card which is missing or not valid is a problem on the card side: {@linkplain UnableToConstructIccKeyException}.
 */

public class UnableToConstructThumbprintKeyException extends InfrastructureMts7Exception {

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
