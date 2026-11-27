package no.entur.abt.bob.mts7.core.exception;

/**
 * The issuer key which the certificate of the card refers to is not among the known issuer keys (door 2), so the trust chain cannot be verified.
 * <p>
 * This is a subclass of {@linkplain TrustChainInvalidCardMts7Exception}, so that it can be told apart from an issuer signature which is not valid, for example
 * to log it separately: a card which refers to a key which nobody has listed may be forged, but this is also how a genuine card looks if the participant
 * metadata is out of date.
 */

public class UnknownIssuerKeyInvalidCardMts7Exception extends TrustChainInvalidCardMts7Exception {

	private static final long serialVersionUID = 1L;

	private final long issuerId;
	private final String keyId;

	/**
	 * Constructor.
	 *
	 * @param issuerId issuer id (iid) from the certificate of the card
	 * @param keyId    key id (kid) from the certificate of the card
	 */

	public UnknownIssuerKeyInvalidCardMts7Exception(long issuerId, String keyId) {
		super("Unknown issuer public key " + keyId + " of participant " + issuerId);
		this.issuerId = issuerId;
		this.keyId = keyId;
	}

	/**
	 * @return the issuer id (iid) from the certificate of the card, i.e. the participant id
	 */

	public long getIssuerId() {
		return issuerId;
	}

	/**
	 * @return the key id (kid) from the certificate of the card
	 */

	public String getKeyId() {
		return keyId;
	}

}
