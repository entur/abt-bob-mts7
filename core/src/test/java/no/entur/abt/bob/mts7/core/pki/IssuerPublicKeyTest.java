package no.entur.abt.bob.mts7.core.pki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.crypto.impl.ECDSA;

public class IssuerPublicKeyTest {

	private static KeyPair ecKeyPair;
	private static KeyPair otherEcKeyPair;
	private static KeyPair rsaKeyPair;

	private static final byte[] DATA = "the data which was signed".getBytes(StandardCharsets.UTF_8);
	private static final byte[] OTHER_DATA = "some other data".getBytes(StandardCharsets.UTF_8);

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
		Signature signature = Signature.getInstance("SHA256withECDSA");
		signature.initSign(key);
		signature.update(data);
		// as in JWS, i.e. r and s concatenated
		return ECDSA.transcodeSignatureToConcat(signature.sign(), 64);
	}

	private static byte[] signRsa(PrivateKey key, byte[] data) throws Exception {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(key);
		signature.update(data);
		return signature.sign();
	}

	private IssuerPublicKey ecKey() {
		return new IssuerPublicKey(10, "10:ec", ecKeyPair.getPublic());
	}

	private IssuerPublicKey rsaKey() {
		return new IssuerPublicKey(11, "11:rsa", rsaKeyPair.getPublic());
	}

	@Test
	public void testGetters() {
		IssuerPublicKey key = ecKey();

		assertEquals(10, key.getPid());
		assertEquals("10:ec", key.getKid());
	}

	@Test
	public void testEcSignature() throws Exception {
		assertTrue(ecKey().verify(DATA, signEc(ecKeyPair.getPrivate(), DATA)));
	}

	@Test
	public void testEcSignatureWithOffset() throws Exception {
		byte[] buffer = new byte[DATA.length + 10];
		System.arraycopy(DATA, 0, buffer, 3, DATA.length);

		assertTrue(ecKey().verify(buffer, 3, DATA.length, signEc(ecKeyPair.getPrivate(), DATA)));
		assertFalse(ecKey().verify(buffer, 0, DATA.length, signEc(ecKeyPair.getPrivate(), DATA)));
	}

	@Test
	public void testEcSignatureForOtherDataIsNotValid() throws Exception {
		assertFalse(ecKey().verify(OTHER_DATA, signEc(ecKeyPair.getPrivate(), DATA)));
	}

	@Test
	public void testEcSignatureFromOtherKeyIsNotValid() throws Exception {
		assertFalse(ecKey().verify(DATA, signEc(otherEcKeyPair.getPrivate(), DATA)));
	}

	@Test
	public void testEcSignatureInDerFormatIsNotValid() throws Exception {
		// signatures are r and s concatenated, not DER
		Signature signature = Signature.getInstance("SHA256withECDSA");
		signature.initSign(ecKeyPair.getPrivate());
		signature.update(DATA);

		assertFalse(ecKey().verify(DATA, signature.sign()));
	}

	@Test
	public void testRsaSignature() throws Exception {
		assertTrue(rsaKey().verify(DATA, signRsa(rsaKeyPair.getPrivate(), DATA)));
		assertFalse(rsaKey().verify(OTHER_DATA, signRsa(rsaKeyPair.getPrivate(), DATA)));
	}

	@Test
	public void testRsaSignatureWithEcSignature() throws Exception {
		assertFalse(rsaKey().verify(DATA, signEc(ecKeyPair.getPrivate(), DATA)));
		assertFalse(ecKey().verify(DATA, signRsa(rsaKeyPair.getPrivate(), DATA)));
	}

	@Test
	public void testMalformedInputIsNotValid() throws Exception {
		IssuerPublicKey key = ecKey();

		assertFalse(key.verify(DATA, new byte[0]));
		assertFalse(key.verify(DATA, new byte[63]));
		assertFalse(key.verify(DATA, new byte[64]));
		assertFalse(key.verify(DATA, new byte[65]));
		assertFalse(key.verify(DATA, null));
		assertFalse(key.verify(DATA, 0, DATA.length + 1, signEc(ecKeyPair.getPrivate(), DATA)));
		assertFalse(key.verify(DATA, -1, 1, signEc(ecKeyPair.getPrivate(), DATA)));
	}

	@Test
	public void testFailedVerificationDoesNotAffectLaterVerification() throws Exception {
		// the same key is used for all cards of an issuer
		byte[] valid = signEc(ecKeyPair.getPrivate(), DATA);

		IssuerPublicKey key = ecKey();

		assertTrue(key.verify(DATA, valid));

		assertFalse(key.verify(DATA, new byte[63]));
		assertTrue(key.verify(DATA, valid));

		assertFalse(key.verify(OTHER_DATA, valid));
		assertTrue(key.verify(DATA, valid));

		byte[] corrupt = valid.clone();
		corrupt[10] ^= 0x01;
		assertFalse(key.verify(DATA, corrupt));
		assertTrue(key.verify(DATA, valid));
	}

	@Test
	public void testRsaFailedVerificationDoesNotAffectLaterVerification() throws Exception {
		byte[] valid = signRsa(rsaKeyPair.getPrivate(), DATA);

		IssuerPublicKey key = rsaKey();

		assertFalse(key.verify(DATA, new byte[10]));
		assertTrue(key.verify(DATA, valid));

		assertFalse(key.verify(OTHER_DATA, valid));
		assertTrue(key.verify(DATA, valid));
	}

	@Test
	public void testConcurrentVerification() throws Exception {
		byte[] valid = signEc(ecKeyPair.getPrivate(), DATA);
		byte[] corrupt = valid.clone();
		corrupt[10] ^= 0x01;

		IssuerPublicKey key = ecKey();

		int threads = 8;
		int iterations = 300;

		ExecutorService executor = Executors.newFixedThreadPool(threads);
		try {
			List<Future<Integer>> futures = new ArrayList<>();
			for (int t = 0; t < threads; t++) {
				futures.add(executor.submit((Callable<Integer>) () -> {
					int wrong = 0;
					for (int i = 0; i < iterations; i++) {
						// a mix of valid and invalid
						if (!key.verify(DATA, valid)) {
							wrong++;
						}
						if (key.verify(DATA, corrupt)) {
							wrong++;
						}
						if (key.verify(DATA, new byte[63])) {
							wrong++;
						}
						if (key.verify(OTHER_DATA, valid)) {
							wrong++;
						}
					}
					return wrong;
				}));
			}

			int wrong = 0;
			for (Future<Integer> future : futures) {
				wrong += future.get();
			}
			assertEquals(0, wrong);
		} finally {
			executor.shutdownNow();
		}
	}

	@Test
	public void testUnsupportedKeyType() throws Exception {
		KeyPairGenerator dsa = KeyPairGenerator.getInstance("DSA");
		dsa.initialize(1024);
		KeyPair keyPair = dsa.generateKeyPair();

		assertThrows(IllegalArgumentException.class, () -> new IssuerPublicKey(1, "1:dsa", keyPair.getPublic()));
		assertThrows(IllegalArgumentException.class, () -> new IssuerPublicKey(1, "1:null", null));
	}

}
