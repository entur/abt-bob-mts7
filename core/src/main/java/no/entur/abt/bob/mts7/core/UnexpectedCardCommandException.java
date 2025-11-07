package no.entur.abt.bob.mts7.core;

import no.entur.abt.bob.mts7.api.Mts7Exception;

public class UnexpectedCardCommandException extends Mts7Exception {

	private static final long serialVersionUID = 1L;

	private byte[] command;
	private byte[] response;

	public UnexpectedCardCommandException() {
		super();
	}

	public UnexpectedCardCommandException(byte[] command, byte[] response) {
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
