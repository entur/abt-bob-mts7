package no.entur.abt.bob.mts7.core.pki;

import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.crypto.impl.ECDSA;

/**
 * Public key of a single card, for verifying that the card has the private key.
 * <p>
 * Instances are thread safe.
 */

public class IccPublicKey {

	private static final Logger LOGGER = LoggerFactory.getLogger(IccPublicKey.class);

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

	public boolean verify(byte[] data, byte[] expected) throws SignatureException {
		return verify(data, 0, data == null ? 0 : data.length, expected);
	}

	public boolean verify(byte[] data, int offset, int length, byte[] expected) throws SignatureException {
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

			// a signature is stateful, so use a new one: it is not shared with anyone, and there is no need to restore it to a known state if something goes
			// wrong
			Signature signature = newSignature();

			signature.update(data, offset, length);
			return signature.verify(encoded);
		} catch (Exception e) {
			LOGGER.info("Unable to verify signature", e);
			return false;
		}
	}

	/**
	 * Create a signature which is initialized for verification with the key.
	 *
	 * @return a new signature
	 * @throws Exception if the algorithm is not available or the key is not accepted
	 */

	Signature newSignature() throws Exception {
		Signature signature;
		if (provider != null) {
			signature = Signature.getInstance(algorithm, provider);
		} else {
			signature = Signature.getInstance(algorithm);
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
