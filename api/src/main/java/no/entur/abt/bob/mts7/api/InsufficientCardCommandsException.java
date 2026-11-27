package no.entur.abt.bob.mts7.api;

/**
 * The reader did not send the commands to retrieve what the card has: the rest of a response which the card said has more (61xx), as GET RESPONSE should follow
 * (MTS7 sections 2.1 and 4.1.3), a command which the card asked to be sent again with other lengths (6Cxx, or 6700 to other lengths than in an example in MTS7
 * which every card must accept, such as an extended Le), or the application-related data (6E) which the select application response did not have, as GET DATA
 * should follow (MTS7 section 4.1.1) (a problem with the reader).
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
		this("Incomplete response: the card has more, but no GET RESPONSE command followed", command, response);
	}

	/**
	 * Constructor.
	 *
	 * @param message  what the reader did not do
	 * @param command  the last command which the reader sent
	 * @param response the response to it, which asks for more
	 */

	public InsufficientCardCommandsException(String message, byte[] command, byte[] response) {
		super(message);
		this.command = command;
		this.response = response;
	}

	/**
	 * Constructor, for data which the reader did not retrieve.
	 *
	 * @param message what is missing
	 */

	public InsufficientCardCommandsException(String message) {
		super(message);
		this.command = null;
		this.response = null;
	}

	public byte[] getCommand() {
		return command;
	}

	public byte[] getResponse() {
		return response;
	}

}
