package no.entur.abt.bob.mts7.core.exception;

import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;

/**
 * The public key of the card (the token public key, <code>tpk</code>, in its certificate) is not as in the specification (MTS1): it is missing, of a type which
 * is not in MTS1 (EC with P-256, or RSA), malformed, or not accepted for its algorithm (a problem on the card side). Thrown by
 * {@linkplain no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory} and {@linkplain no.entur.abt.bob.mts7.core.pki.ThumbprintFactory}.
 */

public class NonCompliantIccKeyInvalidCardMts7Exception extends InvalidCardMts7Exception {

	private static final long serialVersionUID = 1L;

	public NonCompliantIccKeyInvalidCardMts7Exception(String message) {
		super(message);
	}

	public NonCompliantIccKeyInvalidCardMts7Exception(String message, Throwable cause) {
		super(message, cause);
	}

}
