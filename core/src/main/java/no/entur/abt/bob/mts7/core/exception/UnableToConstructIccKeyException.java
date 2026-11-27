package no.entur.abt.bob.mts7.core.exception;

import no.entur.abt.bob.mts7.api.VerifierMts7Exception;

/**
 * The public key of the card is as MTS7 specifies it, but the security provider does not accept it (a problem with the verifier). A public key of the card
 * which is not as specified is a problem on the card side: {@linkplain NonCompliantIccKeyInvalidCardMts7Exception}.
 */

public class UnableToConstructIccKeyException extends VerifierMts7Exception {

	private static final long serialVersionUID = 1L;

	public UnableToConstructIccKeyException(String message, Throwable cause) {
		super(message, cause);
	}

}
