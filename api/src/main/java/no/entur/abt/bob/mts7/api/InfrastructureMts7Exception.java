package no.entur.abt.bob.mts7.api;

/**
 * A problem on our side, not the card's: what verifies the card cannot do its job, for example because an issuer key cannot be created, or the security
 * provider does not have an algorithm. The card may well be valid, so this is not to be reported as an invalid card.
 * <p>
 * The other sides are {@linkplain InvalidCardMts7Exception}, for problems on the card side, and {@linkplain ReaderMts7Exception}, for exchanges with the card
 * which a reader following MTS7 would not send.
 */

public class InfrastructureMts7Exception extends Mts7Exception {

	private static final long serialVersionUID = 1L;

	public InfrastructureMts7Exception() {
		super();
	}

	public InfrastructureMts7Exception(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public InfrastructureMts7Exception(String message, Throwable cause) {
		super(message, cause);
	}

	public InfrastructureMts7Exception(String message) {
		super(message);
	}

	public InfrastructureMts7Exception(Throwable cause) {
		super(cause);
	}

}
