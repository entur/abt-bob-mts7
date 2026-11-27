package no.entur.abt.bob.mts7.core.exception;

import no.entur.abt.bob.mts7.api.VerifierMts7Exception;

/**
 * An issuer key which is among the public keys cannot be used: it cannot be created, is of a type which is not supported, or is not accepted by the security
 * provider (a problem with the verifier).
 */

public class UnableToConstructIssuerKeyException extends VerifierMts7Exception {

	private static final long serialVersionUID = 1L;

	public UnableToConstructIssuerKeyException() {
		super();
	}

	public UnableToConstructIssuerKeyException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public UnableToConstructIssuerKeyException(String message, Throwable cause) {
		super(message, cause);
	}

	public UnableToConstructIssuerKeyException(String message) {
		super(message);
	}

	public UnableToConstructIssuerKeyException(Throwable cause) {
		super(cause);
	}

}
