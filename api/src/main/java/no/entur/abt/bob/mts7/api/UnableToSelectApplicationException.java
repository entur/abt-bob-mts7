package no.entur.abt.bob.mts7.api;

public class UnableToSelectApplicationException extends UnexpectedCardResponseException {

	private static final long serialVersionUID = 1L;

	public UnableToSelectApplicationException() {
		super();
	}

	public UnableToSelectApplicationException(byte[] command, byte[] response) {
		super(command, response);
	}

}
