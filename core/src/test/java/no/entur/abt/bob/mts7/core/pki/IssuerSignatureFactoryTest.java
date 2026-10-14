package no.entur.abt.bob.mts7.core.pki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.impl.ECDSA;

import no.entur.abt.bob.api.pm.model.JwkPublic;
import no.entur.abt.bob.api.pm.model.ParticipantMetadata;

public class IssuerSignatureFactoryTest {

	private static final byte[] DATA = "the data which was signed".getBytes(StandardCharsets.UTF_8);

	private final IssuerSignatureFactory factory = new IssuerSignatureFactory();

	public IssuerSignatureFactoryTest() throws Exception {
	}

	private static String base64Url(BigInteger value, int length) {
		byte[] bytes = value.toByteArray();
		byte[] result = new byte[length];
		int copy = Math.min(bytes.length, length);
		System.arraycopy(bytes, bytes.length - copy, result, length - copy, copy);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(result);
	}

	@Test
	public void testEcKey() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp256r1"));
		KeyPair keyPair = generator.generateKeyPair();
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

		// no alg, as in the participant metadata
		JwkPublic jwk = new JwkPublic().kty("EC")
				.kid("10:ec")
				.crv("P-256")
				.x(base64Url(publicKey.getW().getAffineX(), 32))
				.y(base64Url(publicKey.getW().getAffineY(), 32));

		IssuerPublicKey issuerPublicKey = factory.createIssuerPublicKey(10, jwk);
		assertNotNull(issuerPublicKey);
		assertEquals(10, issuerPublicKey.getPid());
		assertEquals("10:ec", issuerPublicKey.getKid());

		Signature signature = Signature.getInstance("SHA256withECDSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(DATA);

		assertTrue(issuerPublicKey.verify(DATA, ECDSA.transcodeSignatureToConcat(signature.sign(), 64)));
	}

	@Test
	public void testRsaKey() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		KeyPair keyPair = generator.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

		JwkPublic jwk = new JwkPublic().kty("RSA")
				.kid("11:rsa")
				.n(base64Url(publicKey.getModulus(), (publicKey.getModulus().bitLength() + 7) / 8))
				.e(base64Url(publicKey.getPublicExponent(), (publicKey.getPublicExponent().bitLength() + 7) / 8));

		IssuerPublicKey issuerPublicKey = factory.createIssuerPublicKey(11, jwk);
		assertNotNull(issuerPublicKey);
		assertEquals(11, issuerPublicKey.getPid());
		assertEquals("11:rsa", issuerPublicKey.getKid());

		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(DATA);

		assertTrue(issuerPublicKey.verify(DATA, signature.sign()));
	}

	@Test
	public void testAllKeysInParticipantMetadata() throws Exception {
		InputStream is = getClass().getResourceAsStream("/participantMetadata.json");
		List<ParticipantMetadata> participantMetadata = Arrays.asList(new ObjectMapper().readValue(is, ParticipantMetadata[].class));
		assertFalse(participantMetadata.isEmpty());

		int ec = 0;
		int rsa = 0;
		for (ParticipantMetadata p : participantMetadata) {
			for (JwkPublic jwk : p.getMtbPublicKeys()) {
				IssuerPublicKey issuerPublicKey = factory.createIssuerPublicKey(p.getPid(), jwk);

				// the participant metadata does not contain an alg
				assertNotNull(issuerPublicKey, p.getPid() + " " + jwk.getKid());
				assertEquals(jwk.getKid(), issuerPublicKey.getKid());

				if (jwk.getKty().equals("EC")) {
					ec++;
				} else {
					rsa++;
				}
			}
		}
		assertTrue(ec > 0);
		assertTrue(rsa > 0);
	}

}
