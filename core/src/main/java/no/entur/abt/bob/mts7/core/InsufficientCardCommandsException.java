package no.entur.abt.bob.mts7.core;

import no.entur.abt.bob.mts7.api.ReaderMts7Exception;

/**
 * The card said that there is more of its response (61xx), but the reader did not send the GET RESPONSE commands to retrieve it (MTS7, section 4.1.3), so the
 * response is incomplete (a problem with the reader).
 */

public class InsufficientCardCommandsException extends ReaderMts7Exception {

	private static final long serialVersionUID = 1L;

	private final byte[] command;
	private final byte[] response;

	/**
	 * Constructor.
	 *
	 * @param command  the last command of the chain
	 * @param response the response to it, which says that there is more
	 */

	public InsufficientCardCommandsException(byte[] command, byte[] response) {
		super("Incomplete response: the card has more, but no GET RESPONSE command followed");
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
