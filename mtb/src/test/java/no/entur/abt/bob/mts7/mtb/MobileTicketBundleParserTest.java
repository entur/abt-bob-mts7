package no.entur.abt.bob.mts7.mtb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

public class MobileTicketBundleParserTest {

	private static final CBORMapper CBOR = new CBORMapper();

	// genuine card (without the status words)
	private static final String GET_NEXT_DATA = "A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C4603";

	private final MobileTicketBundleParser parser = new MobileTicketBundleParser(CBOR);

	@Test
	public void testParseCard() throws Exception {
		MobileTicketBundle bundle = parser.parse(Hex.decode(GET_NEXT_DATA));

		assertEquals("1", bundle.getMajorVersion());

		// header and (empty) ticket bundle
		assertEquals(2, bundle.getSignedElements().length);
		assertEquals(64, bundle.getSignature().length);

		IssuerSignatureProtectedHeader header = bundle.getIssuerSignatureProtectedHeader();
		assertNotNull(header);
		assertEquals("ES256", header.getAlg());
		assertEquals("10", header.getIid());
		assertEquals("10:20230213", header.getKid());
		assertEquals("6", header.getMiv());
		assertEquals("20230616T110236Z", header.getNbf());
		assertNull(header.getDid());

		TokenPublicKey tpk = header.getTpk();
		assertEquals("EC", tpk.getKty());
		assertEquals("P-256", tpk.getCrv());
		assertNotNull(tpk.getX());
		assertNotNull(tpk.getY());
		assertNull(tpk.getN());
		assertNull(tpk.getE());
	}

	@Test
	public void testSkipsDeviceSignatureProtectedHeader() throws Exception {
		Map<String, Object> device = header();
		device.put("did", "device");

		Map<String, Object> issuer = header();
		issuer.put("kid", "issuer");

		MobileTicketBundle bundle = parser.parse(encode(CBOR.writeValueAsBytes(device), CBOR.writeValueAsBytes(issuer), new byte[] { 1, 2, 3 }));

		assertEquals("issuer", bundle.getIssuerSignatureProtectedHeader().getKid());
		assertArrayEquals(new byte[] { 1, 2, 3 }, bundle.getSignature());
		assertNull(bundle.getMajorVersion());
	}

	@Test
	public void testNoIssuerSignatureProtectedHeader() throws Exception {
		Map<String, Object> withoutKid = header();
		withoutKid.remove("kid");

		MobileTicketBundle bundle = parser.parse(encode(CBOR.writeValueAsBytes(withoutKid), new byte[] { 1 }));

		assertFalse(bundle.hasIssuerSignatureProtectedHeader());
	}

	@Test
	public void testIgnoresUnknownFields() throws Exception {
		Map<String, Object> header = header();
		header.put("xyz", 1);
		@SuppressWarnings("unchecked")
		Map<String, Object> tpk = (Map<String, Object>) header.get("tpk");
		tpk.put("use", "sig");

		MobileTicketBundle bundle = parser.parse(encode(CBOR.writeValueAsBytes(header), new byte[] { 1 }));

		assertEquals("EC", bundle.getIssuerSignatureProtectedHeader().getTpk().getKty());
	}

	@Test
	public void testConvertsIntegerMinorVersionToText() throws Exception {
		// header() encodes miv as a CBOR integer
		MobileTicketBundle bundle = parser.parse(encode(CBOR.writeValueAsBytes(header()), new byte[] { 1 }));

		assertEquals("6", bundle.getIssuerSignatureProtectedHeader().getMiv());
	}

	@Test
	public void testRejectsMissingIssuerSignedTicketBundle() throws Exception {
		assertThrows(IOException.class, () -> parser.parse(CBOR.writeValueAsBytes(new LinkedHashMap<>())));
	}

	@Test
	public void testRejectsBundleWithoutSignedElements() throws Exception {
		assertThrows(IOException.class, () -> parser.parse(encode(new byte[] { 1 })));
	}

	@Test
	public void testRejectsNullElement() throws Exception {
		// CBOR null instead of a byte string, as a signed element or as the signature
		byte[] header = CBOR.writeValueAsBytes(header());
		assertThrows(IOException.class, () -> parser.parse(encode(header, null, new byte[] { 1 })));
		assertThrows(IOException.class, () -> parser.parse(encode(null, header, new byte[] { 1 })));
		assertThrows(IOException.class, () -> parser.parse(encode(header, null)));
	}

	@Test
	public void testSkipsElementWhichIsCborNull() throws Exception {
		// a byte string with CBOR null in it is not an Issuer Signature Protected Header
		byte[] cborNull = CBOR.writeValueAsBytes(null);

		assertFalse(parser.parse(encode(cborNull, new byte[] { 1 })).hasIssuerSignatureProtectedHeader());

		MobileTicketBundle bundle = parser.parse(encode(cborNull, CBOR.writeValueAsBytes(header()), new byte[] { 1 }));
		assertEquals("10", bundle.getIssuerSignatureProtectedHeader().getIid());
	}

	@Test
	public void testEmptyKidOrIidIsNoIssuerSignatureProtectedHeader() throws Exception {
		Map<String, Object> emptyKid = header();
		emptyKid.put("kid", "");
		assertFalse(parser.parse(encode(CBOR.writeValueAsBytes(emptyKid), new byte[] { 1 })).hasIssuerSignatureProtectedHeader());

		Map<String, Object> emptyIid = header();
		emptyIid.put("iid", "");
		assertFalse(parser.parse(encode(CBOR.writeValueAsBytes(emptyIid), new byte[] { 1 })).hasIssuerSignatureProtectedHeader());
	}

	private static Map<String, Object> header() {
		Map<String, Object> tpk = new LinkedHashMap<>();
		tpk.put("kty", "EC");
		tpk.put("crv", "P-256");
		tpk.put("x", "x");
		tpk.put("y", "y");

		Map<String, Object> header = new LinkedHashMap<>();
		header.put("alg", "ES256");
		header.put("iid", "10");
		header.put("kid", "10:test");
		header.put("miv", 6);
		header.put("tpk", tpk);
		return header;
	}

	// the representation of the Issuer Signed Ticket Bundle (MTS1 section 2.3)

	@Test
	public void testSignedDataInTheRecommendedRepresentation() throws Exception {
		MobileTicketBundle bundle = parser.parse(hex(GET_NEXT_DATA));

		assertArrayEquals(new MobileTicketBundleWriter().writeSignedData(bundle.getSignedElements()), bundle.getSignedData());
	}

	@Test
	public void testSignedDataInOtherRepresentations() throws Exception {
		// the signed elements are empty maps (A0), the signature is 03 or 04
		// indefinite length array
		assertSignedData("9F41A041A04103FF", "9F41A041A0FF");
		// count with a one-byte argument
		assertSignedData("980341A041A04103", "980241A041A0");
		// count with a two-byte argument
		assertSignedData("99000341A041A04103", "99000241A041A0");
		// an element with a longer length than needed, which is signed as it is
		assertSignedData("835801A041A04103", "825801A041A0");
		// an indefinite length byte string, which is signed as it is
		assertSignedData("835F42A161426101FF41A04104", "825F42A161426101FF41A0");
	}

	@Test
	public void testElementsOfOtherRepresentations() throws Exception {
		MobileTicketBundle bundle = parser.parse(encodeP(hex("835F42A161426101FF41A04104")));

		// the chunks of the indefinite length byte string are joined
		assertArrayEquals(hex("A1616101"), bundle.getSignedElements()[0]);
		assertArrayEquals(hex("A0"), bundle.getSignedElements()[1]);
		assertArrayEquals(new byte[] { 4 }, bundle.getSignature());
	}

	@Test
	public void testRejectsMalformedIssuerSignedTicketBundle() throws Exception {
		for (String p : new String[] { "", "A0", "41", "83410141", "9F41014102", "9C", "835A0000000141", "825F4101FF" }) {
			assertThrows(IOException.class, () -> parser.parse(encodeP(hex(p))), p);
		}
	}

	private void assertSignedData(String p, String signedData) throws Exception {
		assertArrayEquals(hex(signedData), parser.parse(encodeP(hex(p))).getSignedData(), p);
	}

	private static byte[] hex(String hex) {
		byte[] bytes = new byte[hex.length() / 2];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
		}
		return bytes;
	}

	private static byte[] encodeP(byte[] p) throws Exception {
		Map<String, Object> outer = new LinkedHashMap<>();
		outer.put("p", p);
		return CBOR.writeValueAsBytes(outer);
	}

	private static byte[] encode(byte[]... elements) throws Exception {
		Map<String, Object> outer = new LinkedHashMap<>();
		outer.put("p", CBOR.writeValueAsBytes(elements));
		return CBOR.writeValueAsBytes(outer);
	}

}
