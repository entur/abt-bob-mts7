package no.entur.abt.bob.mts7.core;

import no.entur.abt.bob.mts7.api.InfrastructureMts7Exception;

/**
 * The public key of the card is as MTS7 specifies it, but the security provider does not accept it (a problem on our side). A public key of the card which is
 * not as specified is a problem on the card side: {@linkplain NonCompliantIccKeyInvalidCardMts7Exception}.
 */

public class UnableToConstructIccKeyException extends InfrastructureMts7Exception {

	private static final long serialVersionUID = 1L;

	public UnableToConstructIccKeyException(String message, Throwable cause) {
		super(message, cause);
	}

}
