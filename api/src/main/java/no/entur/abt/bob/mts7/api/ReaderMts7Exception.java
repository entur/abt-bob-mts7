package no.entur.abt.bob.mts7.api;

/**
 * The exchanges with the card are not as a reader following MTS7 would send them: commands are missing, unexpected or malformed (a problem with the reader,
 * such as the control client which sent them, not with the card).
 * <p>
 * The other sides are {@linkplain InvalidCardMts7Exception}, for problems on the card side, and {@linkplain InfrastructureMts7Exception}, for problems on our
 * side.
 */

public class ReaderMts7Exception extends Mts7Exception {

	private static final long serialVersionUID = 1L;

	public ReaderMts7Exception() {
		super();
	}

	public ReaderMts7Exception(String message) {
		super(message);
	}

	public ReaderMts7Exception(String message, Throwable cause) {
		super(message, cause);
	}

}
