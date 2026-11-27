package no.entur.abt.bob.mts7.api;

/**
 * The card did not respond as expected to a command: its status word is not success (a problem on the card side), for example because it does not have the MTS7
 * application ({@linkplain UnableToSelectApplicationException}).
 */

public class UnexpectedCardResponseException extends InvalidCardMts7Exception {

	private static final long serialVersionUID = 1L;

	private byte[] command;
	private byte[] response;

	public UnexpectedCardResponseException() {
		super();
	}

	public UnexpectedCardResponseException(byte[] command, byte[] response) {
		super("Unexpected response from the card" + statusWord(response));
		this.command = command;
		this.response = response;
	}

	private static String statusWord(byte[] response) {
		if (response == null || response.length < 2) {
			return "";
		}
		return String.format(": status word %02X%02X", response[response.length - 2] & 0xFF, response[response.length - 1] & 0xFF);
	}

	public byte[] getCommand() {
		return command;
	}

	public byte[] getResponse() {
		return response;
	}
}
