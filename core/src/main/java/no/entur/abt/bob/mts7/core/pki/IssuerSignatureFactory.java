package no.entur.abt.bob.mts7.core.pki;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeyTypeException;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.crypto.impl.RSASSA;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyConverter;

import no.entur.abt.bob.api.pm.model.JwkPublic;
import no.entur.abt.bob.mts7.core.UnableToConstructIssuerKeyException;

// subclasses of this instance are not thread safe
public class IssuerSignatureFactory {

	protected final Provider provider;

	public IssuerSignatureFactory() throws NoSuchAlgorithmException {
		this(null);
	}

	public IssuerSignatureFactory(Provider provider) {
		this.provider = provider;
	}

	public Signature create(JwkPublic jwkPublic) throws UnableToConstructIssuerKeyException {

		Map<String, Object> fields = convert(jwkPublic);

		try {
			JWK jwk = JWK.parse(fields);

			List<Key> keys = KeyConverter.toJavaKeys(Arrays.asList(jwk));

			Key key = keys.get(0);

			if (RSASSAVerifier.SUPPORTED_ALGORITHMS.contains(jwk.getAlgorithm())) {

				if (!(key instanceof RSAPublicKey)) {
					throw new KeyTypeException(RSAPublicKey.class);
				}

				RSAPublicKey rsaPublicKey = (RSAPublicKey) key;

				Signature signerAndVerifier = RSASSA.getSignerAndVerifier(JWSAlgorithm.RS256, provider);
				signerAndVerifier.initVerify(rsaPublicKey);

				return signerAndVerifier;
			} else if (ECDSAVerifier.SUPPORTED_ALGORITHMS.contains(jwk.getAlgorithm())) {

				if (!(key instanceof ECPublicKey)) {
					throw new KeyTypeException(ECPublicKey.class);
				}

				ECPublicKey ecPublicKey = (ECPublicKey) key;

				Signature signature = ECDSA.getSignerAndVerifier(JWSAlgorithm.ES256, provider);
				signature.initVerify(ecPublicKey);

				return signature;
			}
		} catch (Exception e) {
			throw new UnableToConstructIssuerKeyException(e);
		}

		return null;
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
