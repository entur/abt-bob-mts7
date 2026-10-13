package no.entur.abt.bob.mts7.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import com.nimbusds.jose.crypto.impl.ECDSA;

import no.entur.abt.bob.api.pm.model.JwkPublic;
import no.entur.abt.bob.api.pm.model.ParticipantMetadata;
import no.entur.abt.bob.mts7.core.pki.ParticipantPublicKeys;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

/**
 * Test that the issuer signature (i.e. the trust chain) is actually verified: a card is only trusted if its token public key is vouched for by an issuer key we
 * know.
 */

public class VerifyMts7CardFactoryIssuerSignatureTest {

	// issuer in participantMetadata.json which issued the genuine card below
	private static final String REAL_ISSUER_ID = "10";
	private static final String REAL_ISSUER_KID = "10:20230213";

	private static final byte[] SELECT_APPLICATION_RESPONSE = ByteArrayHexStringConverter
			.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000");
	private static final byte[] GET_DATA_RESPONSE = ByteArrayHexStringConverter.hexStringToByteArray(
			"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000");
	private static final byte[] SIGNATURE_RESPONSE = ByteArrayHexStringConverter.hexStringToByteArray(
			"DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000");

	private static final byte[] CHALLENGE = new byte[32];

	private final CBORMapper cbor = new CBORMapper();

	private ParticipantPublicKeys realIssuers;

	// elements of the genuine card: issuer signature protected header, the second (empty) element and the issuer signature
	private byte[] genuineHeader;
	private byte[] genuineSecondElement;
	private byte[] genuineIssuerSignature;

	@BeforeEach
	public void setup() throws Exception {
		InputStream is = getClass().getResourceAsStream("/participantMetadata.json");
		List<ParticipantMetadata> participantMetadata = Arrays.asList(new ObjectMapper().readValue(is, ParticipantMetadata[].class));
		realIssuers = ParticipantPublicKeys.newBuilder().withParticipants(participantMetadata).build();

		byte[][] elements = elements(withoutStatus(GET_DATA_RESPONSE));
		genuineHeader = elements[0];
		genuineSecondElement = elements[1];
		genuineIssuerSignature = elements[2];
	}

	// helpers

	private static byte[] withoutStatus(byte[] response) {
		return Arrays.copyOf(response, response.length - 2);
	}

	private byte[][] elements(byte[] getData) throws Exception {
		Map<?, ?> outer = cbor.readValue(getData, Map.class);
		return cbor.readValue((byte[]) outer.get("p"), byte[][].class);
	}

	/**
	 * The get data payload for a bundle consisting of the elements.
	 */

	private byte[] bundle(byte[]... elements) throws Exception {
		Map<String, Object> outer = new LinkedHashMap<>();
		outer.put("v", new byte[] { 0x61, 0x31 });
		outer.put("p", cbor.writeValueAsBytes(elements));
		return cbor.writeValueAsBytes(outer);
	}

	private Mts7ApduPayloads payloads(byte[] getData, byte[] internalAuthenticateOutput) {
		Mts7ApduPayloads payloads = new Mts7ApduPayloads();
		payloads.setSelectApplicationOutput(withoutStatus(SELECT_APPLICATION_RESPONSE));
		payloads.setGetDataOutput(getData);
		payloads.setInternalAuthenticateInput(CHALLENGE);
		payloads.setInternalAuthenticateOutput(internalAuthenticateOutput);
		return payloads;
	}

	private static String base64Url(byte[] bytes) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	private static byte[] unsigned(BigInteger value, int length) {
		byte[] bytes = value.toByteArray();
		byte[] result = new byte[length];
		int copy = Math.min(bytes.length, length);
		System.arraycopy(bytes, bytes.length - copy, result, length - copy, copy);
		return result;
	}

	private static KeyPair generateEc() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp256r1"));
		return generator.generateKeyPair();
	}

	private static KeyPair generateRsa() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		return generator.generateKeyPair();
	}

	private static Map<String, Object> tokenPublicKey(KeyPair keyPair) {
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

		Map<String, Object> tpk = new LinkedHashMap<>();
		tpk.put("kty", "EC");
		tpk.put("crv", "P-256");
		tpk.put("x", base64Url(unsigned(publicKey.getW().getAffineX(), 32)));
		tpk.put("y", base64Url(unsigned(publicKey.getW().getAffineY(), 32)));
		return tpk;
	}

	private byte[] header(String issuerId, String issuerKid, KeyPair tokenKeyPair) throws Exception {
		Map<String, Object> header = new LinkedHashMap<>();
		header.put("alg", "ES256");
		header.put("iid", issuerId);
		header.put("kid", issuerKid);
		header.put("miv", 6);
		header.put("tpk", tokenPublicKey(tokenKeyPair));
		return cbor.writeValueAsBytes(header);
	}

	/**
	 * The input to the issuer signature function: a CBOR array of the (separately encoded) elements.
	 */

	private byte[] signedData(byte[]... elements) throws Exception {
		return cbor.writeValueAsBytes(elements);
	}

	private static byte[] signEc(PrivateKey issuerKey, byte[] data) throws Exception {
		Signature signature = Signature.getInstance("SHA256withECDSA");
		signature.initSign(issuerKey);
		signature.update(data);
		return ECDSA.transcodeSignatureToConcat(signature.sign(), 64);
	}

	private static byte[] signRsa(PrivateKey issuerKey, byte[] data) throws Exception {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(issuerKey);
		signature.update(data);
		return signature.sign();
	}

	/**
	 * The response to INTERNAL AUTHENTICATE of a card with the key.
	 */

	private static byte[] internalAuthenticate(KeyPair tokenKeyPair) throws Exception {
		Signature signature = Signature.getInstance("NONEwithECDSA");
		signature.initSign(tokenKeyPair.getPrivate());
		signature.update(CHALLENGE);
		return ECDSA.transcodeSignatureToConcat(signature.sign(), 64);
	}

	private ParticipantPublicKeys issuers(long pid, JwkPublic key) throws Exception {
		ParticipantMetadata participant = new ParticipantMetadata();
		participant.setPid(pid);
		participant.setOrganisationName("Test issuer");
		participant.setMtbPublicKeys(Arrays.asList(key));

		return ParticipantPublicKeys.newBuilder().withParticipant(participant).build();
	}

	private ParticipantPublicKeys ecIssuer(long pid, String kid, KeyPair issuerKeyPair) throws Exception {
		ECPublicKey publicKey = (ECPublicKey) issuerKeyPair.getPublic();

		return issuers(pid,
				new JwkPublic().kty("EC")
						.kid(kid)
						.crv("P-256")
						.x(base64Url(unsigned(publicKey.getW().getAffineX(), 32)))
						.y(base64Url(unsigned(publicKey.getW().getAffineY(), 32))));
	}

	private ParticipantPublicKeys rsaIssuer(long pid, String kid, KeyPair issuerKeyPair) throws Exception {
		RSAPublicKey publicKey = (RSAPublicKey) issuerKeyPair.getPublic();

		return issuers(pid,
				new JwkPublic().kty("RSA")
						.kid(kid)
						.n(base64Url(unsigned(publicKey.getModulus(), (publicKey.getModulus().bitLength() + 7) / 8)))
						.e(base64Url(unsigned(publicKey.getPublicExponent(), (publicKey.getPublicExponent().bitLength() + 7) / 8))));
	}

	private void assertTrusted(ParticipantPublicKeys issuers, Mts7ApduPayloads payloads) throws Exception {
		Mts7Card card = new VerifyMts7CardFactory(issuers).create(payloads);

		assertTrue(card.isVerifiedPrivateKeyPresent());
		assertTrue(card.isVerifiedTrustChain());
	}

	private void assertRejected(ParticipantPublicKeys issuers, Mts7ApduPayloads payloads) throws Exception {
		VerifyMts7CardFactory factory = new VerifyMts7CardFactory(issuers);

		Mts7Card result;
		try {
			result = factory.create(payloads);
		} catch (UnableToVerifyKeyPairException e) {
			result = e.getResult();
		} catch (UnableToVerifyTrustChainException e) {
			result = e.getResult();
		}
		if (result.isVerifiedTrustChain() && result.isVerifiedPrivateKeyPresent()) {
			fail("Card was trusted");
		}
		assertFalse(result.isVerifiedTrustChain(), "Trust chain must not be verified");
	}

	// genuine card

	@Test
	public void testGenuineCardIsTrusted() throws Exception {
		assertTrusted(realIssuers, payloads(withoutStatus(GET_DATA_RESPONSE), withoutStatus(SIGNATURE_RESPONSE)));
	}

	// forgeries, using the real issuer key id

	@Test
	public void testGarbageIssuerSignatureIsRejected() throws Exception {
		byte[] garbage = new byte[64];
		Arrays.fill(garbage, (byte) 0x42);

		byte[] getData = bundle(genuineHeader, genuineSecondElement, garbage);

		assertRejected(realIssuers, payloads(getData, withoutStatus(SIGNATURE_RESPONSE)));
	}

	@Test
	public void testZeroIssuerSignatureOnSelfIssuedCardIsRejected() throws Exception {
		// own key pair, header which names the real issuer, no valid issuer signature
		KeyPair tokenKeyPair = generateEc();

		byte[] header = header(REAL_ISSUER_ID, REAL_ISSUER_KID, tokenKeyPair);
		byte[] getData = bundle(header, genuineSecondElement, new byte[64]);

		assertRejected(realIssuers, payloads(getData, internalAuthenticate(tokenKeyPair)));
	}

	@Test
	public void testSwappedTokenPublicKeyIsRejected() throws Exception {
		// keep the genuine issuer signature, but replace the token public key with our own
		KeyPair tokenKeyPair = generateEc();

		byte[] header = header(REAL_ISSUER_ID, REAL_ISSUER_KID, tokenKeyPair);
		byte[] getData = bundle(header, genuineSecondElement, genuineIssuerSignature);

		assertRejected(realIssuers, payloads(getData, internalAuthenticate(tokenKeyPair)));
	}

	@Test
	public void testSignatureFromAnotherIssuerKeyIsRejected() throws Exception {
		// a perfectly valid issuer signature, but not from the key we trust for this key id
		KeyPair tokenKeyPair = generateEc();
		KeyPair attackerIssuerKeyPair = generateEc();

		byte[] header = header(REAL_ISSUER_ID, REAL_ISSUER_KID, tokenKeyPair);
		byte[] issuerSignature = signEc(attackerIssuerKeyPair.getPrivate(), signedData(header, genuineSecondElement));

		byte[] getData = bundle(header, genuineSecondElement, issuerSignature);

		assertRejected(realIssuers, payloads(getData, internalAuthenticate(tokenKeyPair)));
	}

	@Test
	public void testSignatureOverRawConcatenationIsRejected() throws Exception {
		// the signed data is the CBOR array of the elements, not the elements joined together
		KeyPair tokenKeyPair = generateEc();
		KeyPair issuerKeyPair = generateEc();

		byte[] header = header("77", "77:test", tokenKeyPair);

		ByteArrayOutputStream concatenated = new ByteArrayOutputStream();
		concatenated.write(header);
		concatenated.write(genuineSecondElement);

		byte[] getData = bundle(header, genuineSecondElement, signEc(issuerKeyPair.getPrivate(), concatenated.toByteArray()));

		assertRejected(ecIssuer(77, "77:test", issuerKeyPair), payloads(getData, internalAuthenticate(tokenKeyPair)));
	}

	@Test
	public void testSignatureNotCoveringAllElementsIsRejected() throws Exception {
		KeyPair tokenKeyPair = generateEc();
		KeyPair issuerKeyPair = generateEc();

		byte[] header = header("77", "77:test", tokenKeyPair);

		// signed the header only
		byte[] getData = bundle(header, genuineSecondElement, signEc(issuerKeyPair.getPrivate(), signedData(header)));

		assertRejected(ecIssuer(77, "77:test", issuerKeyPair), payloads(getData, internalAuthenticate(tokenKeyPair)));
	}

	@Test
	public void testUnknownIssuerKeyIdIsRejected() throws Exception {
		KeyPair tokenKeyPair = generateEc();
		KeyPair issuerKeyPair = generateEc();

		byte[] header = header("77", "77:unknown", tokenKeyPair);
		byte[] getData = bundle(header, genuineSecondElement, signEc(issuerKeyPair.getPrivate(), signedData(header, genuineSecondElement)));

		assertRejected(ecIssuer(77, "77:test", issuerKeyPair), payloads(getData, internalAuthenticate(tokenKeyPair)));
	}

	// cards which are correctly signed by an issuer we know

	@Test
	public void testCardSignedByEcIssuerIsTrusted() throws Exception {
		KeyPair tokenKeyPair = generateEc();
		KeyPair issuerKeyPair = generateEc();

		byte[] header = header("77", "77:test", tokenKeyPair);
		byte[] getData = bundle(header, genuineSecondElement, signEc(issuerKeyPair.getPrivate(), signedData(header, genuineSecondElement)));

		assertTrusted(ecIssuer(77, "77:test", issuerKeyPair), payloads(getData, internalAuthenticate(tokenKeyPair)));
	}

	@Test
	public void testCardSignedByRsaIssuerIsTrusted() throws Exception {
		KeyPair tokenKeyPair = generateEc();
		KeyPair issuerKeyPair = generateRsa();

		byte[] header = header("78", "78:test", tokenKeyPair);
		byte[] getData = bundle(header, genuineSecondElement, signRsa(issuerKeyPair.getPrivate(), signedData(header, genuineSecondElement)));

		assertTrusted(rsaIssuer(78, "78:test", issuerKeyPair), payloads(getData, internalAuthenticate(tokenKeyPair)));
	}

	@Test
	public void testCardSignedByWrongRsaIssuerKeyIsRejected() throws Exception {
		KeyPair tokenKeyPair = generateEc();
		KeyPair issuerKeyPair = generateRsa();
		KeyPair attackerIssuerKeyPair = generateRsa();

		byte[] header = header("78", "78:test", tokenKeyPair);
		byte[] getData = bundle(header, genuineSecondElement, signRsa(attackerIssuerKeyPair.getPrivate(), signedData(header, genuineSecondElement)));

		assertRejected(rsaIssuer(78, "78:test", issuerKeyPair), payloads(getData, internalAuthenticate(tokenKeyPair)));
	}

	@Test
	public void testOnlyOneIssuerKeyAtATime() throws Exception {
		// sanity check of the helpers: a signature of the genuine card is not valid for a generated key, and vice versa
		KeyPair tokenKeyPair = generateEc();
		KeyPair issuerKeyPair = generateEc();

		byte[] header = header("77", "77:test", tokenKeyPair);
		byte[] getData = bundle(header, genuineSecondElement, genuineIssuerSignature);

		assertRejected(ecIssuer(77, "77:test", issuerKeyPair), payloads(getData, internalAuthenticate(tokenKeyPair)));
		assertEquals(3, elements(getData).length);
	}

}
