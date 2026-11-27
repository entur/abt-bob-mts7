package no.entur.abt.bob.mts7.core.pki;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Objects;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.impl.ECDSA;

import no.entur.abt.bob.mts7.core.exception.KeyPairInvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.exception.NoSuchAlgorithmMts7Exception;
import no.entur.abt.bob.mts7.core.exception.UnableToConstructIccKeyException;

/**
 * Public key of a single card, for verifying that the card has the private key.
 * <p>
 * Instances are thread safe.
 */

public class IccPublicKey {

	// TOOD key id
	private final PublicKey publicKey;
	private final String algorithm;
	private final Provider provider;

	private final boolean ec;

	/**
	 * Constructor.
	 *
	 * @param publicKey the key
	 * @param algorithm signature algorithm, as in {@linkplain Signature#getInstance(String)}
	 * @param provider  provider, or null for the default
	 */

	public IccPublicKey(PublicKey publicKey, String algorithm, Provider provider) {
		this.publicKey = publicKey;
		this.algorithm = algorithm;
		this.provider = provider;

		this.ec = algorithm.endsWith("ECDSA");
	}

	/**
	 * Verify the signature of the card, i.e. that the card has the private key for its public key (door 3).
	 *
	 * @param data     signed data (the challenge)
	 * @param expected signature from the card
	 * @throws KeyPairInvalidCardMts7Exception  if the signature is not valid, or malformed (a problem on the card side)
	 * @throws UnableToConstructIccKeyException if the security provider does not accept the key of the card (a problem with the verifier)
	 * @throws NoSuchAlgorithmMts7Exception     if the signature algorithm is not available from the security provider (a problem with the verifier)
	 */

	public void verify(byte[] data, byte[] expected) throws KeyPairInvalidCardMts7Exception, UnableToConstructIccKeyException, NoSuchAlgorithmMts7Exception {
		verify(data, 0, data == null ? 0 : data.length, expected);
	}

	/**
	 * Verify the signature of the card, i.e. that the card has the private key for its public key (door 3).
	 *
	 * @param data     buffer with the signed data (the challenge)
	 * @param offset   offset of the signed data in the buffer
	 * @param length   length of the signed data
	 * @param expected signature from the card
	 * @throws KeyPairInvalidCardMts7Exception  if the signature is not valid, or malformed (a problem on the card side)
	 * @throws UnableToConstructIccKeyException if the security provider does not accept the key of the card (a problem with the verifier)
	 * @throws NoSuchAlgorithmMts7Exception     if the signature algorithm is not available from the security provider (a problem with the verifier)
	 */

	public void verify(byte[] data, int offset, int length, byte[] expected)
			throws KeyPairInvalidCardMts7Exception, UnableToConstructIccKeyException, NoSuchAlgorithmMts7Exception {
		// a signature is stateful, so use a new one: it is not shared with anyone, and there is no need to restore it to a known state if something goes
		// wrong. A missing algorithm is a problem with the verifier, so it is not caught here.
		Objects.requireNonNull(data, "data");
		Objects.requireNonNull(expected, "expected");

		Signature signature;
		try {
			signature = newSignature();
		} catch (InvalidKeyException e) {
			// the factory checked that the key is as MTS7 specifies it
			throw new UnableToConstructIccKeyException("The security provider does not accept the public key of the card", e);
		}

		boolean valid;
		try {

			// from MTS7 - 4.1.4. INTERNAL AUTHENTICATE:
			//
			// The response SHALL contain the result of the signing operation:
			//
			// • For ECDSA-capable PICCs the response is the two vectors r and s encoded in a string of
			// octets with big-endian order, each prefixed with zeroes to match the maximum length,
			// concatenated together.
			//
			// • For PICCs relying on RSA the response is the result of xd (mod n) encoded in a string of
			// octets with big-endian order prefixed with zeroes to the length of the modulo.
			//

			byte[] encoded;
			if (ec) {
				encoded = ECDSA.transcodeSignatureToDER(expected);
			} else {
				encoded = expected;
			}

			signature.update(data, offset, length);
			valid = signature.verify(encoded);
		} catch (JOSEException | SignatureException e) {
			// the signature from the card is malformed; anything else (such as a problem with the provider, or a bug) is not caught
			throw new KeyPairInvalidCardMts7Exception("Malformed signature from the card", e);
		}
		if (!valid) {
			throw new KeyPairInvalidCardMts7Exception();
		}
	}

	/**
	 * Create a signature which is initialized for verification with the key.
	 *
	 * @return a new signature
	 * @throws NoSuchAlgorithmMts7Exception if the algorithm is not available (a problem with the verifier)
	 * @throws InvalidKeyException          if the key is not accepted (a problem on the card side)
	 */

	Signature newSignature() throws NoSuchAlgorithmMts7Exception, InvalidKeyException {
		Signature signature;
		try {
			if (provider != null) {
				signature = Signature.getInstance(algorithm, provider);
			} else {
				signature = Signature.getInstance(algorithm);
			}
		} catch (NoSuchAlgorithmException e) {
			throw new NoSuchAlgorithmMts7Exception(algorithm, provider, e);
		}
		signature.initVerify(publicKey);
		return signature;
	}

	/**
	 * @return the type of key, i.e. EC or RSA
	 */

	public String getAlgorithm() {
		return ec ? "EC" : "RSA";
	}
}
