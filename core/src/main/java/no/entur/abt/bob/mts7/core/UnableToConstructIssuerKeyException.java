package no.entur.abt.bob.mts7.core;

import no.entur.abt.bob.mts7.api.Mts7Exception;

public class UnableToConstructIssuerKeyException extends Mts7Exception {

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
