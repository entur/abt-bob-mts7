package no.entur.abt.bob.mts7.core;

/**
 * The public key of the card (the token public key, <code>tpk</code>, in its certificate) cannot be created: it is missing, of a type which is not in MTS1 (EC
 * with P-256, or RSA), or malformed (a problem on the card side). The cause is the {@linkplain UnableToConstructIccKeyException}.
 */

public class IccKeyInvalidCardMts7Exception extends InvalidCardMts7Exception {

	private static final long serialVersionUID = 1L;

	public IccKeyInvalidCardMts7Exception(Mts7Card result, UnableToConstructIccKeyException cause) {
		super("Unable to create ICC public key", result, cause);
	}

}
