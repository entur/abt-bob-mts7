package no.entur.abt.bob.mts7.api;

/**
 * The card is not a valid MTS7 card: a problem on the card side. What the card returned is missing, malformed or not as expected, or the card did not pass
 * verification (see the subclasses).
 * <p>
 * The other sides are {@linkplain ReaderMts7Exception}, for exchanges with the card which a reader following MTS7 would not send, and
 * {@linkplain VerifierMts7Exception}, for problems with the verifier.
 */

public class InvalidCardMts7Exception extends Mts7Exception {

	private static final long serialVersionUID = 1L;

	public InvalidCardMts7Exception() {
		super();
	}

	public InvalidCardMts7Exception(String message) {
		super(message);
	}

	public InvalidCardMts7Exception(String message, Throwable cause) {
		super(message, cause);
	}

}
