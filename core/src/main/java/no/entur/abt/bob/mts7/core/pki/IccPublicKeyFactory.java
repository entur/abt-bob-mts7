package no.entur.abt.bob.mts7.core.pki;

import java.security.Key;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.KeyTypeException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyConverter;

import no.entur.abt.bob.mts7.core.UnableToConstructIccKeyException;

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

	public IccPublicKey create(Map<String, Object> fields) throws UnableToConstructIccKeyException {

		//
		// The Issuer Signature Protected Header SHALL include the following parameters:
		// • alg – Signature Algorithm (string)
		// • iid – Issuer Identifier (string)
		// • kid – Key identifier (string)
		// • miv – Mobile Ticket Specification minor version number (number)
		// o This document defines minor version 6
		//
		// To be able to distinguish between the Issuer Signature and the Device Signature (see section 2.5)
		// header, the Issuer Signature Protected Header MUST NOT contain a did parameter.
		//
		// The Issuer Signature Protected Header MAY include the following parameters:
		// • exp – Signature Expiry (timestamp in ISO 8601:2004 profile basic format, see 2.2 in (MTS8), string)
		// • nbf – Signature Inception (timestamp in ISO 8601:2004 profile basic format, see 2.2 in (MTS8), string)
		// • dsp – Device Signature Provider (string)
		// • dsi – Device Signature Identifier (string)
		// • tpk – Token Public Key (object)
		//

		Map<String, Object> tpk = (Map<String, Object>) fields.get("tpk");

		String algorithm = (String) fields.get("alg");

		try {
			JWK jwk = JWK.parse(tpk);

			List<Key> keys = KeyConverter.toJavaKeys(Arrays.asList(jwk));

			Key key = keys.get(0);

			if (algorithm.equals("RS256")) {

				if (!(key instanceof RSAPublicKey)) {
					throw new KeyTypeException(RSAPublicKey.class);
				}

				return create((RSAPublicKey) key, "NONEwithRSA");
			} else if (algorithm.equals("ES256")) {

				if (!(key instanceof ECPublicKey)) {
					throw new KeyTypeException(ECPublicKey.class);
				}

				return create((ECPublicKey) key, "NoneWithECDSA");
			} else {
				throw new UnableToConstructIccKeyException("Unknown algorithm " + algorithm);
			}
		} catch (Exception e) {
			throw new UnableToConstructIccKeyException(e);
		}
	}

	private IccPublicKey create(PublicKey key, String algorithm) throws Exception {
		IccPublicKey result = new IccPublicKey(key, algorithm, provider);

		// fail now rather than when verifying: make sure that the algorithm is available, and that the key is accepted
		result.newSignature();

		return result;
	}

}
