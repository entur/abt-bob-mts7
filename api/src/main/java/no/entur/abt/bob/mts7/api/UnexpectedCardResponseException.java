package no.entur.abt.bob.mts7.api;

public class UnexpectedCardResponseException extends Mts7Exception {

	private static final long serialVersionUID = 1L;

	private byte[] command;
	private byte[] response;

	public UnexpectedCardResponseException() {
		super();
	}

	public UnexpectedCardResponseException(byte[] command, byte[] response) {
		super();
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
