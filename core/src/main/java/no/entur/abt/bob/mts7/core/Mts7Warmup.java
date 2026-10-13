package no.entur.abt.bob.mts7.core;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import com.nimbusds.jose.crypto.impl.ECDSA;

import no.entur.abt.bob.mts7.core.pki.IccPublicKey;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;

/**
 * Do the work which otherwise is done for the first card, i.e. load classes, initialize the security provider and let the JVM compile the hot code. The first
 * card is much slower than the rest (tens of milliseconds on a desktop), which is a long time for a card which might leave the reader.
 * <p>
 * Warm-up is best effort: it never throws, and a failure only means that the first card is slower.
 */

public class Mts7Warmup {

	private static final Logger LOGGER = LoggerFactory.getLogger(Mts7Warmup.class);

	/**
	 * Exercise the helpers used for each card, with throwaway data.
	 *
	 * @param cborMapper          mapper
	 * @param enricher            card enricher
	 * @param iccPublicKeyFactory factory for the public key of the card
	 */

	public static void warmUp(CBORMapper cborMapper, Mts7CardEnricher enricher, IccPublicKeyFactory iccPublicKeyFactory) {
		try {
			// the empty map and the empty array
			cborMapper.readValue(new byte[] { (byte) 0xA0 }, Map.class);
			cborMapper.readValue(new byte[] { (byte) 0x80 }, byte[][].class);

			enricher.enrichSelectApplicationResponsePayload(new Mts7Card(), new byte[0]);

			warmUpEc(iccPublicKeyFactory);
		} catch (Exception e) {
			LOGGER.debug("Unable to warm up", e);
		}
	}

	private static void warmUpEc(IccPublicKeyFactory iccPublicKeyFactory) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp256r1"));
		KeyPair keyPair = generator.generateKeyPair();

		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

		Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();

		Map<String, Object> tpk = new LinkedHashMap<>();
		tpk.put("kty", "EC");
		tpk.put("crv", "P-256");
		tpk.put("x", encoder.encodeToString(unsigned(publicKey.getW().getAffineX())));
		tpk.put("y", encoder.encodeToString(unsigned(publicKey.getW().getAffineY())));

		Map<String, Object> header = new LinkedHashMap<>();
		header.put("alg", "ES256");
		header.put("tpk", tpk);

		IccPublicKey iccPublicKey = iccPublicKeyFactory.create(header);

		// as the card does: sign the (hashed) challenge without hashing it again
		byte[] challenge = new byte[32];

		Signature signer = Signature.getInstance("NoneWithECDSA");
		signer.initSign(keyPair.getPrivate());
		signer.update(challenge);

		iccPublicKey.verify(challenge, ECDSA.transcodeSignatureToConcat(signer.sign(), 64));
	}

	private static byte[] unsigned(BigInteger value) {
		byte[] bytes = value.toByteArray();

		byte[] result = new byte[32];
		int copy = Math.min(bytes.length, result.length);
		System.arraycopy(bytes, bytes.length - copy, result, result.length - copy, copy);
		return result;
	}

}
