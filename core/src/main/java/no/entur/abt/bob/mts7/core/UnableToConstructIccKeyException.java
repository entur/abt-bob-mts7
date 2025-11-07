package no.entur.abt.bob.mts7.core;

import no.entur.abt.bob.mts7.api.Mts7Exception;

public class UnableToConstructIccKeyException extends Mts7Exception {

	private static final long serialVersionUID = 1L;

	public UnableToConstructIccKeyException() {
		super();
	}

	public UnableToConstructIccKeyException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public UnableToConstructIccKeyException(String message, Throwable cause) {
		super(message, cause);
	}

	public UnableToConstructIccKeyException(String message) {
		super(message);
	}

	public UnableToConstructIccKeyException(Throwable cause) {
		super(cause);
	}

}
