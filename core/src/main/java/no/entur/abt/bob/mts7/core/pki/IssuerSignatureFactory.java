package no.entur.abt.bob.mts7.core.pki;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
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

public class IssuerSignatureFactory {

	protected final Provider provider;

	public IssuerSignatureFactory() throws NoSuchAlgorithmException {
		this(null);
	}

	public IssuerSignatureFactory(Provider provider) {
		this.provider = provider;
	}

	/**
	 * Create issuer public key.
	 *
	 * @param pid       participant (issuer) identifier
	 * @param jwkPublic EC or RSA public key
	 * @return new key
	 * @throws UnableToConstructIssuerKeyException if the key is invalid or not of a supported type
	 */

	public IssuerPublicKey create(long pid, JwkPublic jwkPublic) throws UnableToConstructIssuerKeyException {

		Map<String, Object> fields = convert(jwkPublic);

		Key key;
		try {
			JWK jwk = JWK.parse(fields);

			List<Key> keys = KeyConverter.toJavaKeys(Arrays.asList(jwk));

			key = keys.get(0);
		} catch (Exception e) {
			throw new UnableToConstructIssuerKeyException(e);
		}

		// Use the type of the key, i.e. not the (optional) alg of the JWK, which is not part of the participant metadata.
		if (key instanceof RSAPublicKey || key instanceof ECPublicKey) {
			return new IssuerPublicKey(pid, jwkPublic.getKid(), (PublicKey) key, provider);
		}

		throw new UnableToConstructIssuerKeyException("Unsupported key type " + jwkPublic.getKty());
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
