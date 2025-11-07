package no.entur.abt.bob.mts7.test.record;

import java.util.Arrays;

public class TransceiveInvocation extends AbstractCardInvocation {

	protected byte[] command;
	protected byte[] response;

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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + Arrays.hashCode(command);
		result = prime * result + Arrays.hashCode(response);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		TransceiveInvocation other = (TransceiveInvocation) obj;
		return Arrays.equals(command, other.command) && Arrays.equals(response, other.response);
	}

}
