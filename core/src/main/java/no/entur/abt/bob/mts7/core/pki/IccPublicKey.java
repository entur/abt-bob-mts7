package no.entur.abt.bob.mts7.core.pki;

import java.security.Signature;
import java.security.SignatureException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.crypto.impl.ECDSA;

public class IccPublicKey {

	private static final Logger LOGGER = LoggerFactory.getLogger(IccPublicKey.class);

	// TOOD key id
	protected Signature signature;
	protected String algorithm;

	public IccPublicKey(Signature signature, String algorithm) {
		this.signature = signature;
		this.algorithm = algorithm;
	}

	public boolean verify(byte[] data, byte[] expected) throws SignatureException {
		return verify(data, 0, data.length, expected);
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

			if (algorithm.equals("EC")) {
				final byte[] derSignature = ECDSA.transcodeSignatureToDER(expected);

				signature.update(data, offset, length);
				return signature.verify(derSignature);
			} else if (algorithm.equals("RSA")) {
				signature.update(data, offset, length);
				return signature.verify(expected);
			} else {
				throw new IllegalStateException();
			}
		} catch (Exception e) {
			LOGGER.info("Unable to verify signature", e);
			return false;
		}
	}

	public String getAlgorithm() {
		return algorithm;
	}
}
