package no.entur.abt.bob.mts7.core;

import no.entur.abt.bob.mts7.api.ReaderMts7Exception;

/**
 * Commands which a reader following MTS7 sends are missing from the exchanges with the card (a problem with the reader): select application first, get (next)
 * data, and internal authenticate last.
 */

public class MissingCardCommandsException extends ReaderMts7Exception {

	private static final long serialVersionUID = 1L;

	public MissingCardCommandsException() {
		this("Missing commands in the exchanges with the card");
	}

	public MissingCardCommandsException(String message) {
		super(message);
	}

}
