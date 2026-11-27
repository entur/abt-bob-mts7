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

import no.entur.abt.bob.mts7.core.exception.NoSuchAlgorithmMts7Exception;
import no.entur.abt.bob.mts7.core.exception.TrustChainInvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.exception.UnableToConstructIssuerKeyException;

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
	private final String jwsAlgorithm;
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
		this.jwsAlgorithm = toJwsAlgorithm(algorithm);
		this.provider = provider;

		this.ec = algorithm.endsWith("ECDSA");
	}

	/**
	 * Verify the issuer signature of a card (door 2).
	 *
	 * @param data signed data
	 * @param sign signature
	 * @throws TrustChainInvalidCardMts7Exception  if the signature is not valid, or the data or the signature is malformed (a problem on the card side)
	 * @throws NoSuchAlgorithmMts7Exception        if the signature algorithm is not available from the security provider (a problem with the verifier)
	 * @throws UnableToConstructIssuerKeyException if the key is not accepted by the security provider (a problem with the verifier)
	 */

	public void verify(byte[] data, byte[] sign) throws TrustChainInvalidCardMts7Exception, NoSuchAlgorithmMts7Exception, UnableToConstructIssuerKeyException {
		verify(data, 0, data == null ? 0 : data.length, sign);
	}

	/**
	 * Verify the issuer signature of a card (door 2).
	 *
	 * @param data   buffer with the signed data
	 * @param offset offset of the signed data in the buffer
	 * @param length length of the signed data
	 * @param sign   signature
	 * @throws TrustChainInvalidCardMts7Exception  if the signature is not valid, or the data or the signature is malformed (a problem on the card side)
	 * @throws NoSuchAlgorithmMts7Exception        if the signature algorithm is not available from the security provider (a problem with the verifier)
	 * @throws UnableToConstructIssuerKeyException if the key is not accepted by the security provider (a problem with the verifier)
	 */

	public void verify(byte[] data, int offset, int length, byte[] sign)
			throws TrustChainInvalidCardMts7Exception, NoSuchAlgorithmMts7Exception, UnableToConstructIssuerKeyException {
		// a signature is stateful, so use a new one: it is not shared with anyone, and there is no need to restore it to a known state if something goes
		// wrong. A problem with the algorithm or the key is with the verifier, so it is not caught here.
		Objects.requireNonNull(data, "data");
		Objects.requireNonNull(sign, "sign");

		Signature signature = newSignature();
		boolean valid;
		try {
			byte[] encoded = encode(sign);

			signature.update(data, offset, length);
			valid = signature.verify(encoded);
		} catch (JOSEException | SignatureException e) {
			// the signature from the card is malformed; anything else (such as a problem with the provider, or a bug) is not caught
			throw new TrustChainInvalidCardMts7Exception("Malformed issuer signature", e);
		}
		if (!valid) {
			throw new TrustChainInvalidCardMts7Exception("Issuer signature is not valid");
		}
	}

	private Signature newSignature() throws NoSuchAlgorithmMts7Exception, UnableToConstructIssuerKeyException {
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

	private static String toJwsAlgorithm(String algorithm) {
		if ("SHA256withECDSA".equalsIgnoreCase(algorithm)) {
			return Mts1Algorithms.ES256;
		}
		if ("SHA256withRSA".equalsIgnoreCase(algorithm)) {
			return Mts1Algorithms.RS256;
		}
		return null;
	}

	/**
	 * The algorithm of the issuer signatures which this key verifies, as named by <code>alg</code> in the Issuer Signature Protected Header (MTS1).
	 *
	 * @return ES256, RS256, or null if the signature algorithm is neither
	 */

	public String getJwsAlgorithm() {
		return jwsAlgorithm;
	}

	public long getPid() {
		return pid;
	}

	public String getKid() {
		return kid;
	}
}
