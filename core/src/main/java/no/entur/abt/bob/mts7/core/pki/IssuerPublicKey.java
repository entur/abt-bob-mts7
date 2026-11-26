package no.entur.abt.bob.mts7.core.pki;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.impl.ECDSA;

import no.entur.abt.bob.mts7.core.UnableToConstructIssuerKeyException;

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

	/**
	 * Verify a signature from a card.
	 *
	 * @param data signed data
	 * @param sign signature
	 * @return whether the signature is valid; false also if the data or the signature is malformed (a problem on the card side)
	 * @throws NoSuchAlgorithmException            if the signature algorithm is not available from the security provider (a problem on our side)
	 * @throws UnableToConstructIssuerKeyException if the key is not accepted by the security provider (a problem on our side)
	 */

	public boolean verify(byte[] data, byte[] sign) throws NoSuchAlgorithmException, UnableToConstructIssuerKeyException {
		return verify(data, 0, data == null ? 0 : data.length, sign);
	}

	/**
	 * Verify a signature from a card.
	 *
	 * @param data   buffer with the signed data
	 * @param offset offset of the signed data in the buffer
	 * @param length length of the signed data
	 * @param sign   signature
	 * @return whether the signature is valid; false also if the data or the signature is malformed (a problem on the card side)
	 * @throws NoSuchAlgorithmException            if the signature algorithm is not available from the security provider (a problem on our side)
	 * @throws UnableToConstructIssuerKeyException if the key is not accepted by the security provider (a problem on our side)
	 */

	public boolean verify(byte[] data, int offset, int length, byte[] sign) throws NoSuchAlgorithmException, UnableToConstructIssuerKeyException {
		// a signature is stateful, so use a new one: it is not shared with anyone, and there is no need to restore it to a known state if something goes
		// wrong. A problem with the algorithm or the key is on our side, so it is not caught here.
		Signature signature = newSignature();
		try {
			byte[] encoded = encode(sign);

			signature.update(data, offset, length);
			return signature.verify(encoded);
		} catch (Exception e) {
			// the data or the signature from the card is malformed
			return false;
		}
	}

	private Signature newSignature() throws NoSuchAlgorithmException, UnableToConstructIssuerKeyException {
		Signature signature;
		if (provider != null) {
			signature = Signature.getInstance(algorithm, provider);
		} else {
			signature = Signature.getInstance(algorithm);
		}
		try {
			signature.initVerify(publicKey);
		} catch (InvalidKeyException e) {
			throw new UnableToConstructIssuerKeyException("Issuer public key " + kid + " of participant " + pid + " is not accepted", e);
		}
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
