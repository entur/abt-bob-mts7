package no.entur.abt.bob.mts7.simple.api;

import java.io.ByteArrayOutputStream;

public class Mts7ApduExchange {

	private byte[] command;
	private byte[] response;

	public Mts7ApduExchange() {
	}

	public Mts7ApduExchange(byte[] command, byte[] response) {
		super();
		this.command = command;
		this.response = response;
	}

	public byte[] getCommand() {
		return command;
	}

	public void setCommand(byte[] command) {
		this.command = command;
	}

	public byte[] getResponse() {
		return response;
	}

	public void setResponse(byte[] response) {
		this.response = response;
	}

	public void writeResponsePayload(ByteArrayOutputStream out) {
		out.write(response, 0, response.length - 2);
	}
}
