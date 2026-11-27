package no.entur.abt.bob.mts7.core;

import no.entur.abt.bob.mts7.api.VerifierMts7Exception;

/**
 * The issuer key of the card is not among the issuer public keys, which may be out of date (a problem with the verifier), as an
 * {@linkplain UnknownIssuerKeyPolicy} decided. If the keys are up to date, the card is to blame instead: {@linkplain UnknownIssuerKeyInvalidCardMts7Exception}.
 */

public class OutdatedIssuerKeysException extends VerifierMts7Exception {

	private static final long serialVersionUID = 1L;

	private final long issuerId;
	private final String keyId;

	/**
	 * Constructor.
	 *
	 * @param issuerId issuer id (iid) from the certificate of the card
	 * @param keyId    key id (kid) from the certificate of the card
	 */

	public OutdatedIssuerKeysException(long issuerId, String keyId) {
		super("Unknown issuer public key " + keyId + " of participant " + issuerId + ", and the issuer public keys may be out of date");
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
