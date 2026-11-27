package no.entur.abt.bob.mts7.core.pki;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.crypto.impl.ECDSA;

import no.entur.abt.bob.mts7.core.KeyPairInvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.NoSuchAlgorithmMts7Exception;
import no.entur.abt.bob.mts7.core.NonCompliantIccKeyInvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.UnableToConstructIccKeyException;
import no.entur.abt.bob.mts7.mtb.IssuerSignatureProtectedHeader;
import no.entur.abt.bob.mts7.mtb.TokenPublicKey;
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
		assertDoesNotThrow(() -> ecKey().verify(CHALLENGE, signEc(ecKeyPair.getPrivate(), CHALLENGE)));
	}

	@Test
	public void testEcSignatureWithOffset() throws Exception {
		byte[] buffer = new byte[CHALLENGE.length + 10];
		System.arraycopy(CHALLENGE, 0, buffer, 3, CHALLENGE.length);

		assertDoesNotThrow(() -> ecKey().verify(buffer, 3, CHALLENGE.length, signEc(ecKeyPair.getPrivate(), CHALLENGE)));
		assertThrows(KeyPairInvalidCardMts7Exception.class, () -> ecKey().verify(buffer, 0, CHALLENGE.length, signEc(ecKeyPair.getPrivate(), CHALLENGE)));
	}

	@Test
	public void testEcSignatureForOtherDataIsNotValid() throws Exception {
		assertThrows(KeyPairInvalidCardMts7Exception.class, () -> ecKey().verify(OTHER_CHALLENGE, signEc(ecKeyPair.getPrivate(), CHALLENGE)));
	}

	@Test
	public void testEcSignatureFromOtherKeyIsNotValid() throws Exception {
		assertThrows(KeyPairInvalidCardMts7Exception.class, () -> ecKey().verify(CHALLENGE, signEc(otherEcKeyPair.getPrivate(), CHALLENGE)));
	}

	@Test
	public void testRsaSignature() throws Exception {
		assertDoesNotThrow(() -> rsaKey().verify(CHALLENGE, signRsa(rsaKeyPair.getPrivate(), CHALLENGE)));
		assertThrows(KeyPairInvalidCardMts7Exception.class, () -> rsaKey().verify(OTHER_CHALLENGE, signRsa(rsaKeyPair.getPrivate(), CHALLENGE)));
	}

	@Test
	public void testRsaSignatureWithEcSignature() throws Exception {
		assertThrows(KeyPairInvalidCardMts7Exception.class, () -> rsaKey().verify(CHALLENGE, signEc(ecKeyPair.getPrivate(), CHALLENGE)));
		assertThrows(KeyPairInvalidCardMts7Exception.class, () -> ecKey().verify(CHALLENGE, signRsa(rsaKeyPair.getPrivate(), CHALLENGE)));
	}

	@Test
	public void testMalformedInputIsNotValid() throws Exception {
		assertThrows(KeyPairInvalidCardMts7Exception.class, () -> ecKey().verify(CHALLENGE, new byte[0]));
		assertThrows(KeyPairInvalidCardMts7Exception.class, () -> ecKey().verify(CHALLENGE, new byte[63]));
		assertThrows(KeyPairInvalidCardMts7Exception.class, () -> ecKey().verify(CHALLENGE, new byte[64]));
		assertThrows(KeyPairInvalidCardMts7Exception.class, () -> ecKey().verify(CHALLENGE, new byte[65]));
		assertThrows(KeyPairInvalidCardMts7Exception.class, () -> rsaKey().verify(CHALLENGE, new byte[0]));
	}

	@Test
	public void testMisuseIsNotInvalidCard() throws Exception {
		// a bug of the caller, which must not be reported as a problem on the card side
		assertThrows(NullPointerException.class, () -> ecKey().verify(CHALLENGE, null));
		assertThrows(NullPointerException.class, () -> ecKey().verify(null, signEc(ecKeyPair.getPrivate(), CHALLENGE)));
		assertThrows(NullPointerException.class, () -> rsaKey().verify(CHALLENGE, null));
		assertThrows(IllegalArgumentException.class, () -> ecKey().verify(CHALLENGE, 0, CHALLENGE.length + 1, signEc(ecKeyPair.getPrivate(), CHALLENGE)));
		assertThrows(IllegalArgumentException.class, () -> ecKey().verify(CHALLENGE, -1, 1, signEc(ecKeyPair.getPrivate(), CHALLENGE)));
	}

	@Test
	public void testFailedVerificationDoesNotAffectTheNext() throws Exception {
		// there is no state to restore, so that a key can be used again after any kind of failure
		IccPublicKey key = ecKey();
		byte[] valid = signEc(ecKeyPair.getPrivate(), CHALLENGE);

		assertDoesNotThrow(() -> key.verify(CHALLENGE, valid));
		assertThrows(KeyPairInvalidCardMts7Exception.class, () -> key.verify(CHALLENGE, new byte[64]));
		assertThrows(KeyPairInvalidCardMts7Exception.class, () -> key.verify(CHALLENGE, new byte[3]));
		assertThrows(KeyPairInvalidCardMts7Exception.class, () -> key.verify(OTHER_CHALLENGE, valid));
		assertDoesNotThrow(() -> key.verify(CHALLENGE, valid));
	}

	@Test
	public void testSharedEcKey() throws Exception {
		IccPublicKey key = ecKey();
		byte[] signature = signEc(ecKeyPair.getPrivate(), CHALLENGE);

		List<Throwable> failures = ConcurrentRunner.run(THREADS, 300, (thread, iteration) -> {
			assertDoesNotThrow(() -> key.verify(CHALLENGE, signature));
			assertThrows(KeyPairInvalidCardMts7Exception.class, () -> key.verify(OTHER_CHALLENGE, signature));
		});

		assertEquals(0, failures.size(), "Unexpected failures: " + failures);
	}

	@Test
	public void testSharedRsaKey() throws Exception {
		IccPublicKey key = rsaKey();
		byte[] signature = signRsa(rsaKeyPair.getPrivate(), CHALLENGE);

		List<Throwable> failures = ConcurrentRunner.run(THREADS, 100, (thread, iteration) -> {
			assertDoesNotThrow(() -> key.verify(CHALLENGE, signature));
			assertThrows(KeyPairInvalidCardMts7Exception.class, () -> key.verify(OTHER_CHALLENGE, signature));
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

	private static IssuerSignatureProtectedHeader ecHeader(ECPublicKey publicKey) {
		TokenPublicKey tpk = new TokenPublicKey();
		tpk.setKty("EC");
		tpk.setCrv("P-256");
		tpk.setX(base64Url(publicKey.getW().getAffineX(), 32));
		tpk.setY(base64Url(publicKey.getW().getAffineY(), 32));

		IssuerSignatureProtectedHeader header = new IssuerSignatureProtectedHeader();
		header.setAlg("ES256");
		header.setTpk(tpk);
		return header;
	}

	@Test
	public void testFactoryCreatesEcKey() throws Exception {
		IccPublicKey key = new IccPublicKeyFactory().create(ecHeader((ECPublicKey) ecKeyPair.getPublic()));

		assertEquals("EC", key.getAlgorithm());
		assertDoesNotThrow(() -> key.verify(CHALLENGE, signEc(ecKeyPair.getPrivate(), CHALLENGE)));
		assertThrows(KeyPairInvalidCardMts7Exception.class, () -> key.verify(CHALLENGE, signEc(otherEcKeyPair.getPrivate(), CHALLENGE)));
	}

	@Test
	public void testFactoryCreatesRsaKey() throws Exception {
		RSAPublicKey publicKey = (RSAPublicKey) rsaKeyPair.getPublic();

		TokenPublicKey tpk = new TokenPublicKey();
		tpk.setKty("RSA");
		tpk.setN(base64Url(publicKey.getModulus(), (publicKey.getModulus().bitLength() + 7) / 8));
		tpk.setE(base64Url(publicKey.getPublicExponent(), (publicKey.getPublicExponent().bitLength() + 7) / 8));

		IssuerSignatureProtectedHeader header = new IssuerSignatureProtectedHeader();
		header.setAlg("RS256");
		header.setTpk(tpk);

		IccPublicKey key = new IccPublicKeyFactory().create(header);

		assertEquals("RSA", key.getAlgorithm());
		assertDoesNotThrow(() -> key.verify(CHALLENGE, signRsa(rsaKeyPair.getPrivate(), CHALLENGE)));
	}

	@Test
	public void testFactoryReportsInvalidKeyWhenCreated() {
		IssuerSignatureProtectedHeader header = ecHeader((ECPublicKey) ecKeyPair.getPublic());

		// not a point on the curve
		TokenPublicKey tpk = new TokenPublicKey();
		tpk.setKty("EC");
		tpk.setCrv("P-256");
		tpk.setX("AAAA");
		tpk.setY("AAAA");
		header.setTpk(tpk);

		assertThrows(NonCompliantIccKeyInvalidCardMts7Exception.class, () -> new IccPublicKeyFactory().create(header));
	}

	@Test
	public void testFactoryDoesNotUseTheAlgorithmOfTheIssuerSignature() throws Exception {
		// alg in the header is the algorithm of the issuer signature, so the key of the card follows from its type only
		for (String alg : new String[] { "RS256", "HS256", null }) {
			IssuerSignatureProtectedHeader header = ecHeader((ECPublicKey) ecKeyPair.getPublic());
			header.setAlg(alg);

			IccPublicKey key = new IccPublicKeyFactory().create(header);

			assertEquals("EC", key.getAlgorithm(), alg);
			assertDoesNotThrow(() -> key.verify(CHALLENGE, signEc(ecKeyPair.getPrivate(), CHALLENGE)), alg);
		}
	}

	@Test
	public void testFactoryReportsCurveNotInTheSpecification() throws Exception {
		// MTS1 has P-256 only
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp384r1"));
		ECPublicKey publicKey = (ECPublicKey) generator.generateKeyPair().getPublic();

		TokenPublicKey tpk = new TokenPublicKey();
		tpk.setKty("EC");
		tpk.setCrv("P-384");
		tpk.setX(base64Url(publicKey.getW().getAffineX(), 48));
		tpk.setY(base64Url(publicKey.getW().getAffineY(), 48));

		IssuerSignatureProtectedHeader header = new IssuerSignatureProtectedHeader();
		header.setAlg("ES256");
		header.setTpk(tpk);

		NonCompliantIccKeyInvalidCardMts7Exception e = assertThrows(NonCompliantIccKeyInvalidCardMts7Exception.class,
				() -> new IccPublicKeyFactory().create(header));
		assertEquals("Curve P-384 is not P-256", e.getMessage());
	}

	@Test
	public void testFactoryReportsUnknownKeyType() {
		IssuerSignatureProtectedHeader header = ecHeader((ECPublicKey) ecKeyPair.getPublic());
		header.getTpk().setKty("oct");

		assertThrows(NonCompliantIccKeyInvalidCardMts7Exception.class, () -> new IccPublicKeyFactory().create(header));
	}

	@Test
	public void testUnavailableAlgorithmIsNotInvalidSignature() throws Exception {
		// a problem on our side: the security provider does not have the algorithm
		IccPublicKey key = new IccPublicKey(ecKeyPair.getPublic(), "NoneWithECDSA", new Provider("Empty", "1.0", "Without algorithms") {
			private static final long serialVersionUID = 1L;
		});

		byte[] signature = signEc(ecKeyPair.getPrivate(), CHALLENGE);
		NoSuchAlgorithmMts7Exception e = assertThrows(NoSuchAlgorithmMts7Exception.class, () -> key.verify(CHALLENGE, signature));
		assertInstanceOf(NoSuchAlgorithmException.class, e.getCause());
		assertEquals("NoneWithECDSA", e.getAlgorithm());
	}

	@Test
	public void testKeyNotAcceptedByTheProviderIsNotInvalidCard() throws Exception {
		// a key which the factory created is as MTS7 specifies it, so a provider which does not accept it is a problem on our side
		IccPublicKey key = new IccPublicKey(rsaKeyPair.getPublic(), "NoneWithECDSA", null);

		assertThrows(UnableToConstructIccKeyException.class, () -> key.verify(CHALLENGE, signEc(ecKeyPair.getPrivate(), CHALLENGE)));
	}

	@Test
	public void testFactoryReportsRsaKeyNotInTheSpecification() throws Exception {
		// MTS7 section 2.1: a modulus of 2048 bits
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024);
		RSAPublicKey small = (RSAPublicKey) generator.generateKeyPair().getPublic();
		RSAPublicKey publicKey = (RSAPublicKey) rsaKeyPair.getPublic();

		for (BigInteger[] modulusAndExponent : new BigInteger[][] { { small.getModulus(), small.getPublicExponent() },
				{ publicKey.getModulus().clearBit(0), publicKey.getPublicExponent() }, { publicKey.getModulus(), BigInteger.ONE },
				{ publicKey.getModulus(), BigInteger.valueOf(4) } }) {
			TokenPublicKey tpk = new TokenPublicKey();
			tpk.setKty("RSA");
			tpk.setN(base64Url(modulusAndExponent[0], (modulusAndExponent[0].bitLength() + 7) / 8));
			tpk.setE(base64Url(modulusAndExponent[1], Math.max(1, (modulusAndExponent[1].bitLength() + 7) / 8)));

			IssuerSignatureProtectedHeader header = new IssuerSignatureProtectedHeader();
			header.setTpk(tpk);

			assertThrows(NonCompliantIccKeyInvalidCardMts7Exception.class, () -> new IccPublicKeyFactory().create(header));
		}
	}

	@Test
	public void testFactoryWithoutTheKeyAlgorithmIsNotInvalidCard() {
		// a problem on our side: the security provider does not have the key algorithm
		Provider empty = new Provider("Empty", "1.0", "Without algorithms") {
			private static final long serialVersionUID = 1L;
		};

		NoSuchAlgorithmMts7Exception e = assertThrows(NoSuchAlgorithmMts7Exception.class,
				() -> new IccPublicKeyFactory(empty).create(ecHeader((ECPublicKey) ecKeyPair.getPublic())));
		assertEquals("EC", e.getAlgorithm());
	}

}
