package no.entur.abt.bob.mts7.api;

/**
 * A problem with the verifier, which checks the card, on the device or in the backend: its issuer keys, its security provider or its configuration, for example
 * an issuer key which cannot be created, or an algorithm which the security provider does not have. The card may well be valid, so this is not to be reported
 * as an invalid card.
 * <p>
 * The other sides are {@linkplain InvalidCardMts7Exception}, for problems on the card side, and {@linkplain ReaderMts7Exception}, for exchanges with the card
 * which a reader following MTS7 would not send.
 */

public class VerifierMts7Exception extends Mts7Exception {

	private static final long serialVersionUID = 1L;

	public VerifierMts7Exception() {
		super();
	}

	public VerifierMts7Exception(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public VerifierMts7Exception(String message, Throwable cause) {
		super(message, cause);
	}

	public VerifierMts7Exception(String message) {
		super(message);
	}

	public VerifierMts7Exception(Throwable cause) {
		super(cause);
	}

}
