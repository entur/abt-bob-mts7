package no.entur.abt.bob.mts7.api;

public abstract class Mts7Exception extends Exception {

	public Mts7Exception() {
		super();
	}

	public Mts7Exception(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public Mts7Exception(String message, Throwable cause) {
		super(message, cause);
	}

	public Mts7Exception(String message) {
		super(message);
	}

	public Mts7Exception(Throwable cause) {
		super(cause);
	}

}
