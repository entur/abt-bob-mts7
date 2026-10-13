package no.entur.abt.bob.mts7.core.pki;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyConverter;

import no.entur.abt.bob.api.pm.model.JwkPublic;
import no.entur.abt.bob.mts7.core.UnableToConstructIssuerKeyException;

/**
 * Create issuer keys from participant metadata. Instances are thread safe (and so can be shared), unless a subclass is not.
 */

public class IssuerSignatureFactory {

	protected final Provider provider;

	public IssuerSignatureFactory() throws NoSuchAlgorithmException {
		this(null);
	}

	public IssuerSignatureFactory(Provider provider) {
		this.provider = provider;
	}

	/**
	 * Create an issuer key which can be shared between threads.
	 *
	 * @param pid       participant id
	 * @param jwkPublic key
	 * @return an issuer key, or null if the type of key is not supported
	 * @throws UnableToConstructIssuerKeyException if the key could not be parsed or used
	 */

	public IssuerPublicKey createIssuerPublicKey(long pid, JwkPublic jwkPublic) throws UnableToConstructIssuerKeyException {
		try {
			Key key = parse(jwkPublic);

			// select on the type of the key; the alg of the JWK is not part of the participant metadata
			String algorithm;
			if (key instanceof RSAPublicKey) {
				algorithm = "SHA256withRSA";
			} else if (key instanceof ECPublicKey) {
				algorithm = "SHA256withECDSA";
			} else {
				return null;
			}

			IssuerPublicKey issuerPublicKey = new IssuerPublicKey(pid, jwkPublic.getKid(), (PublicKey) key, algorithm, provider);

			// fail now rather than at each verification: make sure that the algorithm is available, and that the key is accepted
			Signature signature;
			if (provider != null) {
				signature = Signature.getInstance(algorithm, provider);
			} else {
				signature = Signature.getInstance(algorithm);
			}
			signature.initVerify((PublicKey) key);

			return issuerPublicKey;
		} catch (Exception e) {
			throw new UnableToConstructIssuerKeyException(e);
		}
	}

	private Key parse(JwkPublic jwkPublic) throws Exception {
		Map<String, Object> fields = convert(jwkPublic);

		JWK jwk = JWK.parse(fields);

		List<Key> keys = KeyConverter.toJavaKeys(Arrays.asList(jwk));

		return keys.get(0);
	}

	private Map<String, Object> convert(JwkPublic jwkPublic) {
		Map<String, Object> converted = new HashMap<>();

		converted.put("kty", jwkPublic.getKty());
		converted.put("kid", jwkPublic.getKid());
		converted.put("crv", jwkPublic.getCrv());
		converted.put("x", jwkPublic.getX());
		converted.put("y", jwkPublic.getY());
		converted.put("n", jwkPublic.getN());
		converted.put("e", jwkPublic.getE());

		return converted;
	}

}
