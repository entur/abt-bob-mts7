package no.entur.abt.bob.mts7.core.pki;

import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.crypto.impl.ECDSA;

/**
 * Public key of an issuer, used for verifying issuer signatures.
 *
 * <p>
 * Instances are thread safe. A new {@linkplain Signature} is created for every verification, as a {@linkplain Signature} is stateful and a failed verification
 * can leave data from the failed attempt behind, which would make later verifications fail.
 */

public class IssuerPublicKey {

	private static final Logger LOGGER = LoggerFactory.getLogger(IssuerPublicKey.class);

	private final long pid;
	private final String kid;

	private final PublicKey publicKey;
	private final Provider provider;

	public IssuerPublicKey(long pid, String kid, PublicKey publicKey) {
		this(pid, kid, publicKey, null);
	}

	/**
	 * Constructor
	 *
	 * @param pid       participant (issuer) identifier
	 * @param kid       key identifier
	 * @param publicKey EC (ES256) or RSA (RS256) public key
	 * @param provider  security provider, or null for the default
	 */

	public IssuerPublicKey(long pid, String kid, PublicKey publicKey, Provider provider) {
		if (!(publicKey instanceof ECPublicKey) && !(publicKey instanceof RSAPublicKey)) {
			throw new IllegalArgumentException("Expected EC or RSA public key, got " + (publicKey != null ? publicKey.getAlgorithm() : null));
		}
		this.pid = pid;
		this.kid = kid;
		this.publicKey = publicKey;
		this.provider = provider;
	}

	public boolean verify(byte[] data, byte[] sign) {
		return verify(data, 0, data.length, sign);
	}

	/**
	 * Verify a signature.
	 *
	 * @param data   buffer containing the signed data
	 * @param offset offset of the signed data
	 * @param length length of the signed data
	 * @param sign   the signature; for EC keys the two vectors r and s concatenated (as in JWS), for RSA the plain signature
	 * @return true if the signature is valid for the data and this key, false otherwise (including for malformed input)
	 */

	public boolean verify(byte[] data, int offset, int length, byte[] sign) {
		try {
			Signature signature;
			byte[] encodedSignature;
			if (publicKey instanceof ECPublicKey) {
				signature = newSignature("SHA256withECDSA");
				// java expects DER, but signatures are r and s concatenated
				encodedSignature = ECDSA.transcodeSignatureToDER(sign);
			} else {
				signature = newSignature("SHA256withRSA");
				encodedSignature = sign;
			}
			signature.initVerify(publicKey);
			signature.update(data, offset, length);

			return signature.verify(encodedSignature);
		} catch (Exception e) {
			LOGGER.info("Unable to verify issuer signature: " + e);

			return false;
		}
	}

	private Signature newSignature(String algorithm) throws Exception {
		if (provider != null) {
			return Signature.getInstance(algorithm, provider);
		}
		return Signature.getInstance(algorithm);
	}

	public long getPid() {
		return pid;
	}

	public String getKid() {
		return kid;
	}
}
