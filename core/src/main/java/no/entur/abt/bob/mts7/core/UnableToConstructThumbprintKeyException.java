package no.entur.abt.bob.mts7.core;

import no.entur.abt.bob.mts7.api.Mts7Exception;

public class UnableToConstructThumbprintKeyException extends Mts7Exception {

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
