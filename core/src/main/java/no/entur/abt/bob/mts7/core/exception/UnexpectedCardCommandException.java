package no.entur.abt.bob.mts7.core.exception;

import no.entur.abt.bob.mts7.api.ReaderMts7Exception;

/**
 * A command in the exchanges with the card is not one which a reader following MTS7 sends at that point (a problem with the reader).
 */

public class UnexpectedCardCommandException extends ReaderMts7Exception {

	private static final long serialVersionUID = 1L;

	private byte[] command;
	private byte[] response;

	public UnexpectedCardCommandException() {
		super();
	}

	public UnexpectedCardCommandException(byte[] command, byte[] response) {
		super("Unexpected command in the exchanges with the card");
		this.command = command;
		this.response = response;
	}

	public byte[] getCommand() {
		return command;
	}

	public byte[] getResponse() {
		return response;
	}

}
