package no.entur.abt.bob.mts7.core.pki;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;

import no.entur.abt.bob.mts7.core.NoSuchAlgorithmMts7Exception;
import no.entur.abt.bob.mts7.core.NonCompliantIccKeyInvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.UnableToConstructIccKeyException;
import no.entur.abt.bob.mts7.mtb.IssuerSignatureProtectedHeader;
import no.entur.abt.bob.mts7.mtb.TokenPublicKey;

/**
 * Create the public key of a card (the ICC public key). Instances are thread safe, so a single instance can be shared by all threads, and so are the keys it
 * creates.
 */

public class IccPublicKeyFactory {

	/**
	 * The length of the modulus of an RSA key of a card (MTS7 section 2.1)
	 */

	public static final int RSA_MODULUS_BITS = 2048;

	protected final Provider provider;

	public IccPublicKeyFactory() {
		this(null);
	}

	public IccPublicKeyFactory(Provider provider) {
		this.provider = provider;
	}

	/**
	 * @return the security provider, or null for the default
	 */

	public Provider getProvider() {
		return provider;
	}

	/**
	 * Create the public key of a card from its certificate. The algorithm of the signatures of the card follows from the type of the key (EC or RSA), not from
	 * <code>alg</code> in the header, which is the algorithm of the issuer signature (see {@linkplain Mts1Algorithms}).
	 * <p>
	 * The key is first checked to be as MTS7 (section 2.1) specifies it: an EC key on P-256, or an RSA key with a modulus of 2048 bits. Only then is it given
	 * to the security provider, so that a key which the provider does not accept is a problem on our side.
	 *
	 * @param header the Issuer Signature Protected Header of the card
	 * @return the public key of the card
	 * @throws NonCompliantIccKeyInvalidCardMts7Exception if the token public key of the card is missing, of a type which is not in MTS7 (EC with P-256, or RSA
	 *                                                    with a modulus of 2048 bits), or invalid (a problem on the card side)
	 * @throws NoSuchAlgorithmMts7Exception               if the key or signature algorithm is not available from the security provider (a problem on our side)
	 * @throws UnableToConstructIccKeyException           if the security provider does not accept the key (a problem on our side)
	 */

	public IccPublicKey create(IssuerSignatureProtectedHeader header)
			throws NonCompliantIccKeyInvalidCardMts7Exception, NoSuchAlgorithmMts7Exception, UnableToConstructIccKeyException {
		TokenPublicKey tpk = header.getTpk();
		if (tpk == null) {
			throw new NonCompliantIccKeyInvalidCardMts7Exception("Missing token public key");
		}
		if (Mts1Algorithms.ES256.equals(Mts1Algorithms.getTokenAlgorithm(tpk))) {
			return create(toEcPublicKeySpec(tpk), "EC", "NoneWithECDSA");
		}
		if (Mts1Algorithms.RS256.equals(Mts1Algorithms.getTokenAlgorithm(tpk))) {
			return create(toRsaPublicKeySpec(tpk), "RSA", "NONEwithRSA");
		}
		throw new NonCompliantIccKeyInvalidCardMts7Exception("Unknown key type " + tpk.getKty());
	}

	private static ECPublicKeySpec toEcPublicKeySpec(TokenPublicKey tpk) throws NonCompliantIccKeyInvalidCardMts7Exception {
		// MTS1 and MTS7 have P-256 only
		if (!Curve.P_256.getName().equals(tpk.getCrv())) {
			throw new NonCompliantIccKeyInvalidCardMts7Exception("Curve " + tpk.getCrv() + " is not " + Curve.P_256.getName());
		}
		ECKey key;
		try {
			// checks that the point is on the curve
			key = new ECKey.Builder(Curve.P_256, new Base64URL(tpk.getX()), new Base64URL(tpk.getY())).build();
		} catch (RuntimeException e) {
			throw new NonCompliantIccKeyInvalidCardMts7Exception("Invalid EC token public key", e);
		}
		ECPoint point = new ECPoint(key.getX().decodeToBigInteger(), key.getY().decodeToBigInteger());
		return new ECPublicKeySpec(point, Curve.P_256.toECParameterSpec());
	}

	private static RSAPublicKeySpec toRsaPublicKeySpec(TokenPublicKey tpk) throws NonCompliantIccKeyInvalidCardMts7Exception {
		BigInteger modulus;
		BigInteger exponent;
		try {
			modulus = new Base64URL(tpk.getN()).decodeToBigInteger();
			exponent = new Base64URL(tpk.getE()).decodeToBigInteger();
		} catch (RuntimeException e) {
			throw new NonCompliantIccKeyInvalidCardMts7Exception("Invalid RSA token public key", e);
		}
		// MTS7 section 2.1: a modulus of 2048 bits
		if (modulus.bitLength() != RSA_MODULUS_BITS || !modulus.testBit(0)) {
			throw new NonCompliantIccKeyInvalidCardMts7Exception("RSA modulus of " + modulus.bitLength() + " bits, not an odd number of " + RSA_MODULUS_BITS);
		}
		if (exponent.compareTo(BigInteger.ONE) <= 0 || !exponent.testBit(0) || exponent.compareTo(modulus) >= 0) {
			throw new NonCompliantIccKeyInvalidCardMts7Exception("Invalid RSA public exponent");
		}
		return new RSAPublicKeySpec(modulus, exponent);
	}

	private IccPublicKey create(KeySpec spec, String keyAlgorithm, String signatureAlgorithm)
			throws NoSuchAlgorithmMts7Exception, UnableToConstructIccKeyException {
		PublicKey key;
		try {
			KeyFactory keyFactory = provider == null ? KeyFactory.getInstance(keyAlgorithm) : KeyFactory.getInstance(keyAlgorithm, provider);
			key = keyFactory.generatePublic(spec);
		} catch (NoSuchAlgorithmException e) {
			throw new NoSuchAlgorithmMts7Exception(keyAlgorithm, provider, e);
		} catch (InvalidKeySpecException e) {
			// the key is as specified
			throw new UnableToConstructIccKeyException("The security provider does not accept the public key of the card", e);
		}

		IccPublicKey result = new IccPublicKey(key, signatureAlgorithm, provider);

		// fail now rather than when verifying: make sure that the algorithm is available, and that the key is accepted
		try {
			result.newSignature();
		} catch (InvalidKeyException e) {
			throw new UnableToConstructIccKeyException("The security provider does not accept the public key of the card for " + signatureAlgorithm, e);
		}
		return result;
	}

}
