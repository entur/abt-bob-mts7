package no.entur.abt.bob.mts7.core.pki;

import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.impl.ECDSA;

/**
 * Public key of an issuer, for verifying the issuer signature of a card.
 * <p>
 * Instances are thread safe, so a single instance can be shared by all threads (and cards).
 */

public class IssuerPublicKey {

	private final long pid;
	private final String kid;

	private final PublicKey publicKey;
	private final String algorithm;
	private final Provider provider;

	private final boolean ec;

	/**
	 * Constructor.
	 *
	 * @param pid       participant id
	 * @param kid       key id
	 * @param publicKey the key
	 * @param algorithm signature algorithm, as in {@linkplain Signature#getInstance(String)}
	 * @param provider  provider, or null for the default
	 */

	public IssuerPublicKey(long pid, String kid, PublicKey publicKey, String algorithm, Provider provider) {
		this.pid = pid;
		this.kid = kid;

		this.publicKey = publicKey;
		this.algorithm = algorithm;
		this.provider = provider;

		this.ec = algorithm.endsWith("ECDSA");
	}

	public boolean verify(byte[] data, byte[] sign) throws SignatureException {
		return verify(data, 0, data == null ? 0 : data.length, sign);
	}

	public boolean verify(byte[] data, int offset, int length, byte[] sign) throws SignatureException {
		try {
			byte[] encoded = encode(sign);

			// a signature is stateful, so use a new one: it is not shared with anyone, and there is no need to restore it to a known state if something goes
			// wrong
			Signature signature = newSignature();

			signature.update(data, offset, length);
			return signature.verify(encoded);
		} catch (Exception e) {
			return false;
		}
	}

	private Signature newSignature() throws Exception {
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
	 * The signature of an EC key is the two vectors r and s concatenated (as in JWS), but java expects DER.
	 */

	private byte[] encode(byte[] sign) throws JOSEException {
		if (ec) {
			return ECDSA.transcodeSignatureToDER(sign);
		}
		return sign;
	}

	public long getPid() {
		return pid;
	}

	public String getKid() {
		return kid;
	}
}
