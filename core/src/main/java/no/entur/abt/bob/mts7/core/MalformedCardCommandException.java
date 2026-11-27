package no.entur.abt.bob.mts7.core;

import no.entur.abt.bob.mts7.api.ReaderMts7Exception;

/**
 * A command in the exchanges with the card is malformed, or not as MTS7 specifies it, for example a challenge for INTERNAL AUTHENTICATE which is not a SHA-256
 * hash (32 bytes) (a problem with the reader).
 */

public class MalformedCardCommandException extends ReaderMts7Exception {

	private static final long serialVersionUID = 1L;

	public MalformedCardCommandException(String message) {
		super(message);
	}

	public MalformedCardCommandException(String message, Throwable cause) {
		super(message, cause);
	}

}
