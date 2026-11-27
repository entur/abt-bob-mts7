package no.entur.abt.bob.mts7.core;

import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;

/**
 * The card did not prove that it has the private key for the public key in its certificate (door 3), for example because it is a clone.
 */

public class KeyPairInvalidCardMts7Exception extends InvalidCardMts7Exception {

	private static final long serialVersionUID = 1L;

	public KeyPairInvalidCardMts7Exception() {
		this("Unable to verify that private key is present for MTS7 card");
	}

	public KeyPairInvalidCardMts7Exception(String message) {
		super(message);
	}

	public KeyPairInvalidCardMts7Exception(String message, Throwable cause) {
		super(message, cause);
	}

}
