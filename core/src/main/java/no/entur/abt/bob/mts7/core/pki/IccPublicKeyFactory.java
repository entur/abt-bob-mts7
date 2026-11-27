package no.entur.abt.bob.mts7.core.pki;

import java.security.Key;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyConverter;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;

import no.entur.abt.bob.mts7.core.NoSuchAlgorithmMts7Exception;
import no.entur.abt.bob.mts7.core.NonCompliantIccKeyInvalidCardMts7Exception;
import no.entur.abt.bob.mts7.mtb.IssuerSignatureProtectedHeader;
import no.entur.abt.bob.mts7.mtb.TokenPublicKey;

/**
 * Create the public key of a card (the ICC public key). Instances are thread safe, so a single instance can be shared by all threads, and so are the keys it
 * creates.
 */

public class IccPublicKeyFactory {

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
	 *
	 * @param header the Issuer Signature Protected Header of the card
	 * @return the public key of the card
	 * @throws NonCompliantIccKeyInvalidCardMts7Exception if the token public key of the card is missing, of a type which is not in MTS1 (EC with P-256, or
	 *                                                    RSA), or invalid (a problem on the card side)
	 * @throws NoSuchAlgorithmMts7Exception               if the signature algorithm is not available from the security provider (a problem on our side)
	 */

	public IccPublicKey create(IssuerSignatureProtectedHeader header) throws NonCompliantIccKeyInvalidCardMts7Exception, NoSuchAlgorithmMts7Exception {
		TokenPublicKey tpk = header.getTpk();

		try {
			if (tpk == null) {
				throw new NonCompliantIccKeyInvalidCardMts7Exception("Missing token public key");
			}

			JWK jwk = toJwk(tpk);

			List<Key> keys = KeyConverter.toJavaKeys(Arrays.asList(jwk));
			if (keys.isEmpty()) {
				throw new NonCompliantIccKeyInvalidCardMts7Exception("Invalid token public key");
			}

			Key key = keys.get(0);

			if (key instanceof ECPublicKey) {
				return create((ECPublicKey) key, "NoneWithECDSA");
			}
			if (key instanceof RSAPublicKey) {
				return create((RSAPublicKey) key, "NONEwithRSA");
			}
			throw new NonCompliantIccKeyInvalidCardMts7Exception("Unknown key type " + key.getAlgorithm());
		} catch (NonCompliantIccKeyInvalidCardMts7Exception | NoSuchAlgorithmMts7Exception e) {
			throw e;
		} catch (Exception e) {
			throw new NonCompliantIccKeyInvalidCardMts7Exception("Invalid token public key", e);
		}
	}

	private static JWK toJwk(TokenPublicKey tpk) throws NonCompliantIccKeyInvalidCardMts7Exception {
		KeyType keyType = KeyType.parse(tpk.getKty());

		if (KeyType.EC.equals(keyType)) {
			// MTS1 has P-256 only
			if (!Curve.P_256.getName().equals(tpk.getCrv())) {
				throw new NonCompliantIccKeyInvalidCardMts7Exception("Curve " + tpk.getCrv() + " is not " + Curve.P_256.getName());
			}
			return new ECKey.Builder(Curve.P_256, new Base64URL(tpk.getX()), new Base64URL(tpk.getY())).build();
		} else if (KeyType.RSA.equals(keyType)) {
			return new RSAKey.Builder(new Base64URL(tpk.getN()), new Base64URL(tpk.getE())).build();
		}
		throw new NonCompliantIccKeyInvalidCardMts7Exception("Unknown key type " + tpk.getKty());
	}

	private IccPublicKey create(PublicKey key, String algorithm) throws Exception {
		IccPublicKey result = new IccPublicKey(key, algorithm, provider);

		// fail now rather than when verifying: make sure that the algorithm is available, and that the key is accepted
		result.newSignature();

		return result;
	}

}
