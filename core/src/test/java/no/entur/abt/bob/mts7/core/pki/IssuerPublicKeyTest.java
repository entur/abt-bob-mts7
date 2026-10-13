package no.entur.abt.bob.mts7.core.pki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

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

	private static IssuerPublicKey issuerKey(String algorithm, PublicKey publicKey) throws Exception {
		return new IssuerPublicKey(10, "10:test", publicKey, algorithm, null);
	}

	private static IssuerPublicKey ecKey() throws Exception {
		return issuerKey("SHA256withECDSA", ecKeyPair.getPublic());
	}

	private static IssuerPublicKey rsaKey() throws Exception {
		return issuerKey("SHA256withRSA", rsaKeyPair.getPublic());
	}

	@Test
	public void testGetters() throws Exception {
		IssuerPublicKey key = ecKey();

		assertEquals(10, key.getPid());
		assertEquals("10:test", key.getKid());
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
		assertFalse(ecKey().verify(DATA, new byte[0]));
		assertFalse(ecKey().verify(DATA, new byte[63]));
		assertFalse(ecKey().verify(DATA, new byte[64]));
		assertFalse(ecKey().verify(DATA, new byte[65]));
		assertFalse(ecKey().verify(DATA, null));
		assertFalse(ecKey().verify(DATA, 0, DATA.length + 1, signEc(ecKeyPair.getPrivate(), DATA)));
		assertFalse(ecKey().verify(DATA, -1, 1, signEc(ecKeyPair.getPrivate(), DATA)));
	}

}
