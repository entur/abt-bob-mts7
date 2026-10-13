package no.entur.abt.bob.mts7.core.pki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.crypto.impl.ECDSA;

import no.entur.abt.bob.mts7.core.UnableToConstructIccKeyException;
import no.entur.abt.bob.mts7.test.util.ConcurrentRunner;

public class IccPublicKeyTest {

	private static KeyPair ecKeyPair;
	private static KeyPair otherEcKeyPair;
	private static KeyPair rsaKeyPair;

	// the challenge, which is (the hash) signed as it is
	private static final byte[] CHALLENGE = new byte[32];
	private static final byte[] OTHER_CHALLENGE = new byte[32];

	static {
		for (int i = 0; i < CHALLENGE.length; i++) {
			CHALLENGE[i] = (byte) i;
			OTHER_CHALLENGE[i] = (byte) (i + 1);
		}
	}

	private static final int THREADS = 8;

	@BeforeAll
	public static void generateKeys() throws Exception {
		KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
		ec.initialize(new ECGenParameterSpec("secp256r1"));
		ecKeyPair = ec.generateKeyPair();
		otherEcKeyPair = ec.generateKeyPair();

		KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
		rsa.initialize(2048);
		rsaKeyPair = rsa.generateKeyPair();
	}

	private static byte[] signEc(PrivateKey key, byte[] data) throws Exception {
		Signature signature = Signature.getInstance("NoneWithECDSA");
		signature.initSign(key);
		signature.update(data);
		// as the card: r and s concatenated, not DER
		return ECDSA.transcodeSignatureToConcat(signature.sign(), 64);
	}

	private static byte[] signRsa(PrivateKey key, byte[] data) throws Exception {
		Signature signature = Signature.getInstance("NONEwithRSA");
		signature.initSign(key);
		signature.update(data);
		return signature.sign();
	}

	private static IccPublicKey ecKey() {
		return new IccPublicKey(ecKeyPair.getPublic(), "NoneWithECDSA", null);
	}

	private static IccPublicKey rsaKey() {
		return new IccPublicKey(rsaKeyPair.getPublic(), "NONEwithRSA", null);
	}

	@Test
	public void testAlgorithm() {
		assertEquals("EC", ecKey().getAlgorithm());
		assertEquals("RSA", rsaKey().getAlgorithm());
	}

	@Test
	public void testEcSignature() throws Exception {
		assertTrue(ecKey().verify(CHALLENGE, signEc(ecKeyPair.getPrivate(), CHALLENGE)));
	}

	@Test
	public void testEcSignatureWithOffset() throws Exception {
		byte[] buffer = new byte[CHALLENGE.length + 10];
		System.arraycopy(CHALLENGE, 0, buffer, 3, CHALLENGE.length);

		assertTrue(ecKey().verify(buffer, 3, CHALLENGE.length, signEc(ecKeyPair.getPrivate(), CHALLENGE)));
		assertFalse(ecKey().verify(buffer, 0, CHALLENGE.length, signEc(ecKeyPair.getPrivate(), CHALLENGE)));
	}

	@Test
	public void testEcSignatureForOtherDataIsNotValid() throws Exception {
		assertFalse(ecKey().verify(OTHER_CHALLENGE, signEc(ecKeyPair.getPrivate(), CHALLENGE)));
	}

	@Test
	public void testEcSignatureFromOtherKeyIsNotValid() throws Exception {
		assertFalse(ecKey().verify(CHALLENGE, signEc(otherEcKeyPair.getPrivate(), CHALLENGE)));
	}

	@Test
	public void testRsaSignature() throws Exception {
		assertTrue(rsaKey().verify(CHALLENGE, signRsa(rsaKeyPair.getPrivate(), CHALLENGE)));
		assertFalse(rsaKey().verify(OTHER_CHALLENGE, signRsa(rsaKeyPair.getPrivate(), CHALLENGE)));
	}

	@Test
	public void testRsaSignatureWithEcSignature() throws Exception {
		assertFalse(rsaKey().verify(CHALLENGE, signEc(ecKeyPair.getPrivate(), CHALLENGE)));
		assertFalse(ecKey().verify(CHALLENGE, signRsa(rsaKeyPair.getPrivate(), CHALLENGE)));
	}

	@Test
	public void testMalformedInputIsNotValid() throws Exception {
		assertFalse(ecKey().verify(CHALLENGE, new byte[0]));
		assertFalse(ecKey().verify(CHALLENGE, new byte[63]));
		assertFalse(ecKey().verify(CHALLENGE, new byte[64]));
		assertFalse(ecKey().verify(CHALLENGE, new byte[65]));
		assertFalse(ecKey().verify(CHALLENGE, null));
		assertFalse(ecKey().verify(null, signEc(ecKeyPair.getPrivate(), CHALLENGE)));
		assertFalse(ecKey().verify(CHALLENGE, 0, CHALLENGE.length + 1, signEc(ecKeyPair.getPrivate(), CHALLENGE)));
		assertFalse(ecKey().verify(CHALLENGE, -1, 1, signEc(ecKeyPair.getPrivate(), CHALLENGE)));

		assertFalse(rsaKey().verify(CHALLENGE, new byte[0]));
		assertFalse(rsaKey().verify(CHALLENGE, null));
	}

	@Test
	public void testFailedVerificationDoesNotAffectTheNext() throws Exception {
		// there is no state to restore, so that a key can be used again after any kind of failure
		IccPublicKey key = ecKey();
		byte[] valid = signEc(ecKeyPair.getPrivate(), CHALLENGE);

		assertTrue(key.verify(CHALLENGE, valid));
		assertFalse(key.verify(CHALLENGE, new byte[64]));
		assertFalse(key.verify(CHALLENGE, new byte[3]));
		assertFalse(key.verify(OTHER_CHALLENGE, valid));
		assertTrue(key.verify(CHALLENGE, valid));
	}

	@Test
	public void testSharedEcKey() throws Exception {
		IccPublicKey key = ecKey();
		byte[] signature = signEc(ecKeyPair.getPrivate(), CHALLENGE);

		List<Throwable> failures = ConcurrentRunner.run(THREADS, 300, (thread, iteration) -> {
			assertTrue(key.verify(CHALLENGE, signature));
			assertFalse(key.verify(OTHER_CHALLENGE, signature));
		});

		assertEquals(0, failures.size(), "Unexpected failures: " + failures);
	}

	@Test
	public void testSharedRsaKey() throws Exception {
		IccPublicKey key = rsaKey();
		byte[] signature = signRsa(rsaKeyPair.getPrivate(), CHALLENGE);

		List<Throwable> failures = ConcurrentRunner.run(THREADS, 100, (thread, iteration) -> {
			assertTrue(key.verify(CHALLENGE, signature));
			assertFalse(key.verify(OTHER_CHALLENGE, signature));
		});

		assertEquals(0, failures.size(), "Unexpected failures: " + failures);
	}

	// created by the factory

	private static String base64Url(BigInteger value, int length) {
		byte[] bytes = value.toByteArray();
		byte[] result = new byte[length];
		int copy = Math.min(bytes.length, length);
		System.arraycopy(bytes, bytes.length - copy, result, length - copy, copy);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(result);
	}

	private static Map<String, Object> ecHeader(ECPublicKey publicKey) {
		Map<String, Object> tpk = new LinkedHashMap<>();
		tpk.put("kty", "EC");
		tpk.put("crv", "P-256");
		tpk.put("x", base64Url(publicKey.getW().getAffineX(), 32));
		tpk.put("y", base64Url(publicKey.getW().getAffineY(), 32));

		Map<String, Object> header = new LinkedHashMap<>();
		header.put("alg", "ES256");
		header.put("tpk", tpk);
		return header;
	}

	@Test
	public void testFactoryCreatesEcKey() throws Exception {
		IccPublicKey key = new IccPublicKeyFactory().create(ecHeader((ECPublicKey) ecKeyPair.getPublic()));

		assertEquals("EC", key.getAlgorithm());
		assertTrue(key.verify(CHALLENGE, signEc(ecKeyPair.getPrivate(), CHALLENGE)));
		assertFalse(key.verify(CHALLENGE, signEc(otherEcKeyPair.getPrivate(), CHALLENGE)));
	}

	@Test
	public void testFactoryCreatesRsaKey() throws Exception {
		RSAPublicKey publicKey = (RSAPublicKey) rsaKeyPair.getPublic();

		Map<String, Object> tpk = new LinkedHashMap<>();
		tpk.put("kty", "RSA");
		tpk.put("n", base64Url(publicKey.getModulus(), (publicKey.getModulus().bitLength() + 7) / 8));
		tpk.put("e", base64Url(publicKey.getPublicExponent(), (publicKey.getPublicExponent().bitLength() + 7) / 8));

		Map<String, Object> header = new LinkedHashMap<>();
		header.put("alg", "RS256");
		header.put("tpk", tpk);

		IccPublicKey key = new IccPublicKeyFactory().create(header);

		assertEquals("RSA", key.getAlgorithm());
		assertTrue(key.verify(CHALLENGE, signRsa(rsaKeyPair.getPrivate(), CHALLENGE)));
	}

	@Test
	public void testFactoryReportsInvalidKeyWhenCreated() {
		Map<String, Object> header = ecHeader((ECPublicKey) ecKeyPair.getPublic());

		// not a point on the curve
		Map<String, Object> tpk = new LinkedHashMap<>();
		tpk.put("kty", "EC");
		tpk.put("crv", "P-256");
		tpk.put("x", "AAAA");
		tpk.put("y", "AAAA");
		header.put("tpk", tpk);

		assertThrows(UnableToConstructIccKeyException.class, () -> new IccPublicKeyFactory().create(header));
	}

	@Test
	public void testFactoryReportsAlgorithmWhichDoesNotMatchTheKey() {
		Map<String, Object> header = ecHeader((ECPublicKey) ecKeyPair.getPublic());
		header.put("alg", "RS256");

		assertThrows(UnableToConstructIccKeyException.class, () -> new IccPublicKeyFactory().create(header));
	}

}
