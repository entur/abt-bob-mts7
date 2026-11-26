package no.entur.abt.bob.mts7.core;

/**
 * The certificate of the card was not signed by a known issuer (door 2): the issuer key is unknown (the subclass
 * {@linkplain UnknownIssuerKeyInvalidCardMts7Exception}), or the issuer signature is not valid. A known issuer key which cannot be used is a problem on our
 * side, see {@linkplain UnableToConstructIssuerKeyException}.
 */

public class TrustChainInvalidCardMts7Exception extends InvalidCardMts7Exception {

	private static final long serialVersionUID = 1L;

	public TrustChainInvalidCardMts7Exception(Mts7Card result) {
		this("Unable to verify trust chain for MTS7 card", result);
	}

	public TrustChainInvalidCardMts7Exception(String message, Mts7Card result) {
		super(message, result);
	}

}
