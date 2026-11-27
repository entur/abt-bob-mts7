package no.entur.abt.bob.mts7.core.pki;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import com.nimbusds.jose.crypto.impl.ECDSA;

import no.entur.abt.bob.mts7.core.NoSuchAlgorithmMts7Exception;
import no.entur.abt.bob.mts7.mtb.IssuerSignatureProtectedHeader;

public class IccPublicKeyBuilderTest {

	private static final CBORMapper CBOR = new CBORMapper();

	private static KeyPair issuerKeyPair;
	private static KeyPair tokenKeyPair;

	@BeforeAll
	public static void generateKeys() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp256r1"));

		issuerKeyPair = generator.generateKeyPair();
		tokenKeyPair = generator.generateKeyPair();
	}

	private static byte[] bytes(int length, int seed) {
		byte[] result = new byte[length];
		for (int i = 0; i < length; i++) {
			result[i] = (byte) (seed + i);
		}
		return result;
	}

	private static byte[] unsigned(BigInteger value) {
		byte[] bytes = value.toByteArray();
		byte[] result = new byte[32];
		int copy = Math.min(bytes.length, 32);
		System.arraycopy(bytes, bytes.length - copy, result, 32 - copy, copy);
		return result;
	}

	private static Map<String, Object> header() {
		return header("ES256");
	}

	/**
	 * @param alg the algorithm of the issuer signature, or null for none
	 */

	private static Map<String, Object> header(String alg) {
		ECPublicKey publicKey = (ECPublicKey) tokenKeyPair.getPublic();
		Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();

		Map<String, Object> tpk = new LinkedHashMap<>();
		tpk.put("kty", "EC");
		tpk.put("crv", "P-256");
		tpk.put("x", encoder.encodeToString(unsigned(publicKey.getW().getAffineX())));
		tpk.put("y", encoder.encodeToString(unsigned(publicKey.getW().getAffineY())));

		Map<String, Object> header = new LinkedHashMap<>();
		if (alg != null) {
			header.put("alg", alg);
		}
		header.put("iid", "10");
		header.put("kid", "10:test");
		header.put("tpk", tpk);
		return header;
	}

	private static IssuerSignatureProtectedHeader issuerSignatureProtectedHeader() {
		return issuerSignatureProtectedHeader(header());
	}

	private static IssuerSignatureProtectedHeader issuerSignatureProtectedHeader(Map<String, Object> header) {
		return CBOR.convertValue(header, IssuerSignatureProtectedHeader.class);
	}

	private static byte[] sign(PrivateKey key, byte[] data) throws Exception {
		Signature signature = Signature.getInstance("SHA256withECDSA");
		signature.initSign(key);
		signature.update(data);
		return ECDSA.transcodeSignatureToConcat(signature.sign(), 64);
	}

	private IccPublicKeyBuilder newBuilder() {
		return new IccPublicKeyBuilder(new IccPublicKeyFactory());
	}

	private IssuerPublicKey issuerKey() throws Exception {
		return new IssuerPublicKey(10, "10:test", issuerKeyPair.getPublic(), "SHA256withECDSA", null);
	}

	/**
	 * Builder with the (CBOR encoded) header and a second element, signed by the issuer.
	 */

	private IccPublicKeyBuilder signedBuilder() throws Exception {
		return signedBuilder(header(), issuerKey());
	}

	private IccPublicKeyBuilder signedBuilder(Map<String, Object> headerMap, IssuerPublicKey issuerKey) throws Exception {
		byte[] header = CBOR.writeValueAsBytes(headerMap);
		byte[] second = new byte[] { (byte) 0xA0 };

		byte[] signature = sign(issuerKeyPair.getPrivate(), CBOR.writeValueAsBytes(new byte[][] { header, second }));

		return newBuilder().withSignedData(header, 0, header.length)
				.withSignedData(second, 0, second.length)
				.withSignature(signature)
				.withIssuerPublicKey(issuerKey)
				.withIssuerSignatureProtectedHeader(issuerSignatureProtectedHeader(headerMap));
	}

	/**
	 * The issuer key, with a security provider which does not have any algorithms, so that verifying fails on our side.
	 */

	private IssuerPublicKey issuerKeyWithoutAlgorithms() {
		return new IssuerPublicKey(10, "10:test", issuerKeyPair.getPublic(), "SHA256withECDSA", new Provider("Empty", "1.0", "Without algorithms") {
			private static final long serialVersionUID = 1L;
		});
	}

	// signed data encoding

	@Test
	public void testSignedDataIsCborArrayOfByteStrings() throws Exception {
		// lengths around the boundaries where the encoding of the length changes
		int[] lengths = { 0, 1, 23, 24, 25, 255, 256, 257, 65535, 65536, 70000 };
		// counts around the boundaries where the encoding of the array length changes
		int[] counts = { 1, 2, 3, 23, 24, 25, 255, 256, 257 };

		for (int count : counts) {
			for (int length : lengths) {
				// a lot of data for the largest combinations, so use short elements for all but the first
				byte[][] elements = new byte[count][];
				IccPublicKeyBuilder builder = newBuilder();
				for (int i = 0; i < count; i++) {
					elements[i] = bytes(i == 0 ? length : Math.min(length, 300), i);
					builder.withSignedData(elements[i], 0, elements[i].length);
				}

				assertArrayEquals(CBOR.writeValueAsBytes(elements), builder.getSignedData(), "count " + count + ", length " + length);
			}
		}
	}

	@Test
	public void testSignedDataIsEncodedAsInTheGenuineCard() throws Exception {
		// 82 58B1 <177 bytes> 41 A0
		byte[] header = bytes(177, 0);

		IccPublicKeyBuilder builder = newBuilder().withSignedData(header, 0, header.length).withSignedData(new byte[] { (byte) 0xA0 }, 0, 1);

		byte[] expected = new byte[1 + 2 + 177 + 2];
		expected[0] = (byte) 0x82;
		expected[1] = 0x58;
		expected[2] = (byte) 0xB1;
		System.arraycopy(header, 0, expected, 3, 177);
		expected[180] = 0x41;
		expected[181] = (byte) 0xA0;

		assertArrayEquals(expected, builder.getSignedData());
	}

	@Test
	public void testSignedDataUsesOffsetAndLength() {
		byte[] buffer = { 1, 2, 3, 4, 5 };

		IccPublicKeyBuilder builder = newBuilder().withSignedData(buffer, 1, 3);

		assertArrayEquals(new byte[] { (byte) 0x81, 0x43, 2, 3, 4 }, builder.getSignedData());
	}

	@Test
	public void testSignedDataIsCopied() {
		byte[] buffer = { 1, 2, 3 };

		IccPublicKeyBuilder builder = newBuilder().withSignedData(buffer, 0, buffer.length);
		buffer[0] = 99;

		assertArrayEquals(new byte[] { (byte) 0x81, 0x43, 1, 2, 3 }, builder.getSignedData());
	}

	// build

	@Test
	public void testBuildWithValidSignature() throws Exception {
		IccPublicKeyBuilder builder = signedBuilder();

		assertTrue(builder.canBuild());

		IccPublicKey key = builder.build();
		assertNotNull(key);
		assertEquals("EC", key.getAlgorithm());
	}

	@Test
	public void testBuildWithInvalidSignature() throws Exception {
		IccPublicKeyBuilder builder = signedBuilder().withSignature(new byte[64]);

		// there is enough data to try
		assertTrue(builder.canBuild());

		assertThrows(SignatureException.class, builder::build);
	}

	@Test
	public void testBuildWithSignatureFromOtherKey() throws Exception {
		byte[] header = CBOR.writeValueAsBytes(header());

		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp256r1"));
		KeyPair other = generator.generateKeyPair();

		IccPublicKeyBuilder builder = signedBuilder()
				.withSignature(sign(other.getPrivate(), CBOR.writeValueAsBytes(new byte[][] { header, new byte[] { (byte) 0xA0 } })));

		assertThrows(SignatureException.class, builder::build);
	}

	@Test
	public void testBuildWithChangedData() throws Exception {
		// valid signature, but not for these elements
		byte[] header = CBOR.writeValueAsBytes(header());
		byte[] second = new byte[] { (byte) 0xA0 };

		byte[] signature = sign(issuerKeyPair.getPrivate(), CBOR.writeValueAsBytes(new byte[][] { header, second }));

		byte[] changed = header.clone();
		changed[changed.length - 1] ^= 0x01;

		IccPublicKeyBuilder builder = newBuilder().withSignedData(changed, 0, changed.length)
				.withSignedData(second, 0, second.length)
				.withSignature(signature)
				.withIssuerPublicKey(issuerKey())
				.withIssuerSignatureProtectedHeader(issuerSignatureProtectedHeader());

		assertThrows(SignatureException.class, builder::build);
	}

	// the algorithm of the issuer signature

	@Test
	public void testBuildWithoutAlgorithm() throws Exception {
		IccPublicKeyBuilder builder = signedBuilder(header(null), issuerKey());

		SignatureException e = assertThrows(SignatureException.class, builder::build);
		assertEquals("Issuer signature algorithm null is not ES256 or RS256", e.getMessage());
	}

	@Test
	public void testBuildWithAlgorithmNotInTheSpecification() throws Exception {
		// signed with the issuer key, but the card names an algorithm which is not in MTS1
		for (String alg : new String[] { "", "none", "HS256", "ES384", "PS256", "es256" }) {
			IccPublicKeyBuilder builder = signedBuilder(header(alg), issuerKey());

			SignatureException e = assertThrows(SignatureException.class, builder::build, alg);
			assertEquals("Issuer signature algorithm " + alg + " is not ES256 or RS256", e.getMessage());
		}
	}

	@Test
	public void testBuildWithAlgorithmWhichDoesNotMatchTheIssuerKey() throws Exception {
		// RS256 is in MTS1, but the issuer key is EC
		IccPublicKeyBuilder builder = signedBuilder(header("RS256"), issuerKey());

		SignatureException e = assertThrows(SignatureException.class, builder::build);
		assertEquals("Issuer signature algorithm RS256 does not match issuer public key 10:test of participant 10 (ES256)", e.getMessage());
	}

	@Test
	public void testAlgorithmNotInTheSpecificationIsBlamedOnTheCard() throws Exception {
		// verifying would fail on our side, but the card is checked first
		IccPublicKeyBuilder builder = signedBuilder(header("HS256"), issuerKeyWithoutAlgorithms());

		assertThrows(SignatureException.class, builder::build);
	}

	@Test
	public void testAlgorithmInTheSpecificationIsNotBlamedOnTheCard() throws Exception {
		// the card is as in the specification, so a problem when verifying is on our side
		IccPublicKeyBuilder builder = signedBuilder(header(), issuerKeyWithoutAlgorithms());

		assertThrows(NoSuchAlgorithmMts7Exception.class, builder::build);
	}

	@Test
	public void testBuildWithoutEnoughData() {
		IccPublicKeyBuilder builder = newBuilder();
		assertFalse(builder.canBuild());

		builder.withSignedData(new byte[] { 1 }, 0, 1).withSignature(new byte[64]).withIssuerSignatureProtectedHeader(issuerSignatureProtectedHeader());
		// no issuer key
		assertFalse(builder.canBuild());
	}

	@Test
	public void testReset() throws Exception {
		IccPublicKeyBuilder builder = signedBuilder();
		assertTrue(builder.canBuild());

		builder.reset();

		assertFalse(builder.canBuild());
	}

	@Test
	public void testResetForgetsTheHeaderOfTheEarlierCard() throws Exception {
		IccPublicKeyBuilder builder = signedBuilder();
		builder.reset();

		// everything for a new card except the header, so the header of the earlier card must not be used
		byte[] element = new byte[] { 1 };
		builder.withSignedData(element, 0, element.length).withSignature(new byte[64]).withIssuerPublicKey(issuerKey());

		assertFalse(builder.canBuild());
	}

}
