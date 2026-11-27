package no.entur.abt.bob.mts7.core;

/**
 * The public key of the card (the token public key, <code>tpk</code>, in its certificate) is missing, of a type which is not in MTS1, or not valid (a problem
 * on the card side).
 * <p>
 * Thrown by {@linkplain no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory} and {@linkplain no.entur.abt.bob.mts7.core.pki.ThumbprintFactory}, which do not
 * have the card, so {@linkplain #getResult()} is an empty card. The card factories and processors throw {@linkplain IccKeyInvalidCardMts7Exception} instead,
 * with the card as far as it was read, and this as the cause.
 */

public class UnableToConstructIccKeyException extends InvalidCardMts7Exception {

	private static final long serialVersionUID = 1L;

	public UnableToConstructIccKeyException(String message) {
		super(message, new Mts7Card());
	}

	public UnableToConstructIccKeyException(String message, Throwable cause) {
		super(message, new Mts7Card(), cause);
	}

	public UnableToConstructIccKeyException(Throwable cause) {
		this(cause == null ? null : cause.toString(), cause);
	}

}
