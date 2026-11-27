package no.entur.abt.bob.mts7.core;

import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;

/**
 * The certificate of the card was not signed by a known issuer (door 2): the issuer key is unknown (the subclass
 * {@linkplain UnknownIssuerKeyInvalidCardMts7Exception}), or the issuer signature is not valid. A known issuer key which cannot be used is a problem with the
 * verifier, see {@linkplain UnableToConstructIssuerKeyException}.
 */

public class TrustChainInvalidCardMts7Exception extends InvalidCardMts7Exception {

	private static final long serialVersionUID = 1L;

	public TrustChainInvalidCardMts7Exception() {
		this("Unable to verify trust chain for MTS7 card");
	}

	public TrustChainInvalidCardMts7Exception(String message) {
		super(message);
	}

	public TrustChainInvalidCardMts7Exception(String message, Throwable cause) {
		super(message, cause);
	}

}
