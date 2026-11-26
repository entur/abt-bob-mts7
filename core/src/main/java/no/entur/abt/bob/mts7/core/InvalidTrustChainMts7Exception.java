package no.entur.abt.bob.mts7.core;

/**
 * The certificate of the card was not signed by a known issuer (door 2): the issuer key is unknown or not supported, or the issuer signature is not valid.
 */

public class InvalidTrustChainMts7Exception extends InvalidCardMts7Exception {

	private static final long serialVersionUID = 1L;

	public InvalidTrustChainMts7Exception(Mts7Card result) {
		this("Unable to verify trust chain for MTS7 card", result);
	}

	public InvalidTrustChainMts7Exception(String message, Mts7Card result) {
		super(message, result);
	}

}
