package no.entur.abt.bob.mts7.core;

import no.entur.abt.bob.mts7.api.ReaderMts7Exception;

/**
 * A response in the exchanges with the card cannot be from a card: it is missing, or shorter than the two bytes of its status word (a problem with the reader,
 * as a card always responds with a status word).
 */

public class MalformedCardResponseException extends ReaderMts7Exception {

	private static final long serialVersionUID = 1L;

	public MalformedCardResponseException(String message) {
		super(message);
	}

}
