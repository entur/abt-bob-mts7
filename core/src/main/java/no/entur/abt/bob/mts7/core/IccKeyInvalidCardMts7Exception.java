package no.entur.abt.bob.mts7.core;

import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;

/**
 * The public key of the card (the token public key, <code>tpk</code>, in its certificate) cannot be created: it is missing, of a type which is not in MTS1 (EC
 * with P-256, or RSA), or malformed (a problem on the card side). Thrown by {@linkplain no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory} and
 * {@linkplain no.entur.abt.bob.mts7.core.pki.ThumbprintFactory}.
 */

public class IccKeyInvalidCardMts7Exception extends InvalidCardMts7Exception {

	private static final long serialVersionUID = 1L;

	public IccKeyInvalidCardMts7Exception(String message) {
		super(message);
	}

	public IccKeyInvalidCardMts7Exception(String message, Throwable cause) {
		super(message, cause);
	}

}
