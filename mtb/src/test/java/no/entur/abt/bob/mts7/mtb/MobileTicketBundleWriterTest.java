package no.entur.abt.bob.mts7.mtb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

public class MobileTicketBundleWriterTest {

	// ECDSA with the r||s signature encoding used by JWS and BoB
	private static final String ES256 = "SHA256withECDSAinP1363Format";

	// genuine card, issuer 10 (without the status words)
	private static final String CARD = "A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C4603";

	// MTS7 sample of Hallandstrafiken (issuer 22), from https://github.com/bobcat-ticketing/bob-mtb-samples (test keys only)
	private static final String HLT = "a26176426131617058fa8358b3a663696964623232636b69646d6d7473372d3230313930393233636e6266703230323030313033"
			+ "543134333735385a6374706ba4636b74796245436363727665502d3235366178782b7575436e3175666b6c6c71417a4b32563733"
			+ "78535a4a337a5866707a645769585254467947336571307a4d6179782b64685f79526135615a586e634f5f3464536d544a336232"
			+ "4b6d4b70416269784b64706c485f4d6748776a4563616c67654553323536636d6976613641a05840328901596a33883760377781"
			+ "a882487bef29cc3c7cc7a308489dce6d4e6feb63da6948959ba447e092959d21c97038d8a6a8a431ef44663f7e8e8e84532cb267";

	private static final String HLT_ISSUER_X = "15xvtrO_3uAqK9fTD_rizKNNTfKr8amaDwd3xxEUoBE";
	private static final String HLT_ISSUER_Y = "khVOdad6uY0uW69J66u6WcBj2H8eZLwOEcYPwWhi6Ds";

	private final MobileTicketBundleParser parser = new MobileTicketBundleParser();
	private final MobileTicketBundleWriter writer = new MobileTicketBundleWriter();

	@Test
	public void testRoundTripsSamples() throws Exception {
		for (String sample : new String[] { CARD, HLT }) {
			byte[] bytes = Hex.decode(sample);

			assertArrayEquals(bytes, writer.write(parser.parse(bytes)));
		}
	}

	@Test
	public void testWritesHeaderAsIssuedOnCard() throws Exception {
		// this issuer uses the same order of the parameters as the writer
		MobileTicketBundle bundle = parser.parse(Hex.decode(CARD));

		assertArrayEquals(bundle.getSignedElements()[0], writer.writeIssuerSignatureProtectedHeader(bundle.getIssuerSignatureProtectedHeader()));
	}

	@Test
	public void testVerifiesSampleSignature() throws Exception {
		MobileTicketBundle bundle = parser.parse(Hex.decode(HLT));

		assertTrue(verify(bundle, p256PublicKey(HLT_ISSUER_X, HLT_ISSUER_Y)));

		// miv "6" -> "7"
		byte[][] tampered = bundle.getSignedElements().clone();
		tampered[0] = tampered[0].clone();
		tampered[0][tampered[0].length - 1] = '7';
		assertFalse(verify(new MobileTicketBundle(tampered, bundle.getSignature(), null), p256PublicKey(HLT_ISSUER_X, HLT_ISSUER_Y)));
	}

	@Test
	public void testIssuesIdMobileTicketBundle() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp256r1"));
		KeyPair issuerKey = generator.generateKeyPair();

		IssuerSignatureProtectedHeader header = header();
		byte[][] signedElements = new byte[][] { writer.writeIssuerSignatureProtectedHeader(header), MobileTicketBundleWriter.emptyTicketBundle() };

		Signature signer = Signature.getInstance(ES256);
		signer.initSign(issuerKey.getPrivate());
		signer.update(writer.writeSignedData(signedElements));

		byte[] encoded = writer.write(new MobileTicketBundle(signedElements, signer.sign(), header));

		MobileTicketBundle parsed = parser.parse(encoded);
		assertEquals(MobileTicketBundle.MAJOR_VERSION, parsed.getMajorVersion());
		assertArrayEquals(new byte[] { (byte) 0xA0 }, parsed.getSignedElements()[1]);
		assertEquals("ES256", parsed.getIssuerSignatureProtectedHeader().getAlg());
		assertEquals("4242", parsed.getIssuerSignatureProtectedHeader().getIid());
		assertEquals("6", parsed.getIssuerSignatureProtectedHeader().getMiv());
		assertEquals("P-256", parsed.getIssuerSignatureProtectedHeader().getTpk().getCrv());
		assertTrue(verify(parsed, issuerKey.getPublic()));
	}

	@Test
	public void testWritesDefiniteLengthsInFixedOrder() throws Exception {
		IssuerSignatureProtectedHeader header = header();
		header.setExp("20261009T000000Z");

		byte[] encoded = writer.writeIssuerSignatureProtectedHeader(header);

		// definite length map with 7 entries, miv as text string
		assertEquals(0xA7, encoded[0] & 0xFF);
		assertTrue(Hex.toString(encoded).contains("636d69766136"));

		@SuppressWarnings("unchecked")
		Map<String, Object> decoded = new CBORMapper().readValue(encoded, LinkedHashMap.class);
		assertArrayEquals(new Object[] { "alg", "iid", "kid", "miv", "exp", "nbf", "tpk" }, decoded.keySet().toArray());
		@SuppressWarnings("unchecked")
		Map<String, Object> tpk = (Map<String, Object>) decoded.get("tpk");
		assertArrayEquals(new Object[] { "kty", "crv", "x", "y" }, tpk.keySet().toArray());
	}

	@Test
	public void testWritesRsaTokenPublicKey() throws Exception {
		IssuerSignatureProtectedHeader header = header();
		TokenPublicKey tpk = new TokenPublicKey();
		tpk.setKty("RSA");
		tpk.setN("n");
		tpk.setE("AQAB");
		header.setTpk(tpk);

		TokenPublicKey decoded = parser.parse(writer.write(new MobileTicketBundle(
				new byte[][] { writer.writeIssuerSignatureProtectedHeader(header), MobileTicketBundleWriter.emptyTicketBundle() }, new byte[] { 1 }, header)))
				.getIssuerSignatureProtectedHeader()
				.getTpk();

		assertEquals("RSA", decoded.getKty());
		assertEquals("n", decoded.getN());
		assertEquals("AQAB", decoded.getE());
		assertNull(decoded.getCrv());
	}

	@Test
	public void testRejectsHeaderNotConformingToSpecification() throws Exception {
		assertRejected(h -> h.setAlg(null));
		assertRejected(h -> h.setKid(null));
		assertRejected(h -> h.setIid(null));
		assertRejected(h -> h.setIid("0"));
		assertRejected(h -> h.setMiv(null));
		assertRejected(h -> h.setMiv("6.1"));
		assertRejected(h -> h.setDid("device"));
		assertRejected(h -> h.setDsi("device"));
		assertRejected(h -> h.setDsp("x"));
		assertRejected(h -> h.getTpk().setKty("OKP"));
		assertRejected(h -> h.getTpk().setCrv("P-384"));
		assertRejected(h -> h.getTpk().setY(null));
		assertRejected(h -> h.getTpk().setE("AQAB"));
	}

	@Test
	public void testAcceptsOptionalParameters() throws Exception {
		IssuerSignatureProtectedHeader header = header();
		header.setIid("@4242");
		header.setDsp("10");
		header.setDsi("device");
		header.setTpk(null);

		IssuerSignatureProtectedHeader decoded = new MobileTicketBundleParser().parse(writer.write(new MobileTicketBundle(
				new byte[][] { writer.writeIssuerSignatureProtectedHeader(header), MobileTicketBundleWriter.emptyTicketBundle() }, new byte[] { 1 }, header)))
				.getIssuerSignatureProtectedHeader();

		assertEquals("@4242", decoded.getIid());
		assertEquals("10", decoded.getDsp());
		assertEquals("device", decoded.getDsi());
		assertFalse(decoded.isDeviceSignatureProtectedHeader());
	}

	@Test
	public void testWritesSignedDataWithDefiniteLengths() throws Exception {
		assertEquals("8241014102", Hex.toString(writer.writeSignedData(new byte[][] { { 1 }, { 2 } })));

		// one element, as read from a card, for verification
		assertEquals("8141aa", Hex.toString(writer.writeSignedData(new byte[][] { { (byte) 0xAA } })));

		byte[] large = new byte[300];
		assertTrue(Hex.toString(writer.writeSignedData(new byte[][] { large, MobileTicketBundleWriter.emptyTicketBundle() })).startsWith("8259012c"));
	}

	@Test
	public void testNormalisesAndWritesLongStringsWithDefiniteLength() throws Exception {
		IssuerSignatureProtectedHeader header = header();
		// 'a' followed by a combining ring above is written as 'å'
		header.setKid("a\u030A");
		assertTrue(Hex.toString(writer.writeIssuerSignatureProtectedHeader(header)).contains("636b696462c3a5"));

		StringBuilder kid = new StringBuilder();
		for (int i = 0; i < 300; i++) {
			kid.append('k');
		}
		header.setKid(kid.toString());
		assertTrue(Hex.toString(writer.writeIssuerSignatureProtectedHeader(header)).contains("636b696479012c"));
	}

	@Test
	public void testRejectsIncompleteBundle() throws Exception {
		IssuerSignatureProtectedHeader header = header();
		byte[][] onlyHeader = new byte[][] { writer.writeIssuerSignatureProtectedHeader(header) };
		byte[][] signedElements = new byte[][] { onlyHeader[0], MobileTicketBundleWriter.emptyTicketBundle() };

		assertThrows(IllegalArgumentException.class, () -> writer.writeSignedData(new byte[0][]));
		assertThrows(IllegalArgumentException.class, () -> writer.write(new MobileTicketBundle(onlyHeader, new byte[] { 1 }, header)));
		assertThrows(IllegalArgumentException.class, () -> writer.write(new MobileTicketBundle(signedElements, new byte[0], header)));
		assertThrows(IllegalArgumentException.class, () -> writer.write(new MobileTicketBundle(null, signedElements, new byte[] { 1 }, header)));
	}

	private interface Modification {
		void apply(IssuerSignatureProtectedHeader header);
	}

	private void assertRejected(Modification modification) {
		IssuerSignatureProtectedHeader header = header();
		modification.apply(header);
		assertThrows(IllegalArgumentException.class, () -> writer.writeIssuerSignatureProtectedHeader(header));
	}

	private static IssuerSignatureProtectedHeader header() {
		TokenPublicKey tpk = new TokenPublicKey();
		tpk.setKty("EC");
		tpk.setCrv("P-256");
		tpk.setX("uuCn1ufkllqAzK2V73xSZJ3zXfpzdWiXRTFyG3eq0zM");
		tpk.setY("dh_yRa5aZXncO_4dSmTJ3b2KmKpAbixKdplH_MgHwjE");

		IssuerSignatureProtectedHeader header = new IssuerSignatureProtectedHeader();
		header.setAlg("ES256");
		header.setIid("4242");
		header.setKid("4242:mts7-20261008");
		header.setMiv("6");
		header.setNbf("20261008T123456Z");
		header.setTpk(tpk);
		return header;
	}

	private boolean verify(MobileTicketBundle bundle, PublicKey publicKey) throws Exception {
		Signature verifier = Signature.getInstance(ES256);
		verifier.initVerify(publicKey);
		verifier.update(writer.writeSignedData(bundle.getSignedElements()));
		return verifier.verify(bundle.getSignature());
	}

	private static PublicKey p256PublicKey(String x, String y) throws Exception {
		AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
		parameters.init(new ECGenParameterSpec("secp256r1"));
		ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);

		ECPoint point = new ECPoint(new BigInteger(1, Base64.getUrlDecoder().decode(x)), new BigInteger(1, Base64.getUrlDecoder().decode(y)));
		return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec));
	}

}
