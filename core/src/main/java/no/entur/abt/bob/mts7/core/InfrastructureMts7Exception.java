package no.entur.abt.bob.mts7.core;

import no.entur.abt.bob.mts7.api.Mts7Exception;

/**
 * A problem on our side, not the card's: what verifies the card cannot do its job, for example because an issuer key cannot be created, or the security
 * provider does not have an algorithm. The card may well be valid, so this is not to be reported as an invalid card.
 * <p>
 * Problems on the card side are reported with {@linkplain InvalidCardMts7Exception}.
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
