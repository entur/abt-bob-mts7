package no.entur.abt.bob.mts7.core;

import no.entur.abt.bob.mts7.api.Mts7Exception;

/**
 * The card is not a valid MTS7 card: a problem on the card side. Either what the card returned is missing or malformed, or (for the subclasses
 * {@linkplain InvalidKeyPairMts7Exception} and {@linkplain InvalidTrustChainMts7Exception}) the card did not pass verification.
 * <p>
 * Problems on our side, such as an issuer key which cannot be constructed or a signature algorithm which the security provider does not have, are reported with
 * other exceptions.
 */

public class InvalidCardMts7Exception extends Mts7Exception {

	private static final long serialVersionUID = 1L;

	private final Mts7Card result;

	public InvalidCardMts7Exception(String message, Mts7Card result) {
		super(message);
		this.result = result;
	}

	public InvalidCardMts7Exception(String message, Mts7Card result, Throwable cause) {
		super(message, cause);
		this.result = result;
	}

	/**
	 * @return the card as far as it was read; nothing in it can be trusted
	 */

	public Mts7Card getResult() {
		return result;
	}

}
