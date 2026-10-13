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
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

/**
 * Do the work which otherwise is done for the first card, i.e. load classes, initialize the security provider and let the JVM compile the hot code. The first
 * card is much slower than the rest (tens of milliseconds on a desktop), which is a long time for a card which might leave the reader.
 * <p>
 * Warm-up is best effort: it never throws, and a failure only means that the first card is slower.
 */

public class Mts7Warmup {

	private static final Logger LOGGER = LoggerFactory.getLogger(Mts7Warmup.class);

	// the responses (without the status words) of a genuine card to 'select application' and 'get next data'
	private static final byte[] SAMPLE_SELECT_APPLICATION_PAYLOAD = ByteArrayHexStringConverter
			.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F66080202010502020102");
	private static final byte[] SAMPLE_GET_DATA_PAYLOAD = ByteArrayHexStringConverter.hexStringToByteArray(
			"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C4603");

	/**
	 * Exercise the helpers used for each card, with throwaway data.
	 *
	 * @param cborMapper          mapper
	 * @param enricher            card enricher
	 * @param iccPublicKeyFactory factory for the public key of the card
	 */

	public static void warmUp(CBORMapper cborMapper, Mts7CardEnricher enricher, IccPublicKeyFactory iccPublicKeyFactory) {
		try {
			parseSampleCard(cborMapper, enricher);

			warmUpEc(iccPublicKeyFactory);
		} catch (Exception e) {
			LOGGER.debug("Unable to warm up", e);
		}
	}

	/**
	 * Parse the data of a genuine card (its public data only) as the card factories do, so that the same classes and code paths are used for the first real card.
	 *
	 * @param cborMapper mapper
	 * @param enricher   card enricher
	 * @return the card
	 * @throws Exception if the sample could not be parsed
	 */

	@SuppressWarnings("unchecked")
	static Mts7Card parseSampleCard(CBORMapper cborMapper, Mts7CardEnricher enricher) throws Exception {
		Mts7Card card = new Mts7Card();

		enricher.enrichSelectApplicationResponsePayload(card, SAMPLE_SELECT_APPLICATION_PAYLOAD);

		Map<String, Object> outer = cborMapper.readValue(SAMPLE_GET_DATA_PAYLOAD, Map.class);

		byte[][] elements = cborMapper.readValue((byte[]) outer.get("p"), byte[][].class);

		// the last element is the signature
		for (int i = 0; i < elements.length - 1; i++) {
			cborMapper.readValue(elements[i], Map.class);
		}
		return card;
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
