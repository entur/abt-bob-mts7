package no.entur.abt.bob.mts7.core.mtb;

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

import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

public class MobileTicketBundleParserTest {

	private static final CBORMapper CBOR = new CBORMapper();

	// genuine card (without the status words)
	private static final String GET_NEXT_DATA = "A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C4603";

	private final MobileTicketBundleParser parser = new MobileTicketBundleParser(CBOR);

	@Test
	public void testParseCard() throws Exception {
		MobileTicketBundle bundle = parser.parse(ByteArrayHexStringConverter.hexStringToByteArray(GET_NEXT_DATA));

		assertEquals("1", bundle.getMajorVersion());

		// header and (empty) ticket bundle
		assertEquals(2, bundle.getSignedElements().length);
		assertEquals(64, bundle.getSignature().length);

		IssuerSignatureProtectedHeader header = bundle.getIssuerSignatureProtectedHeader();
		assertNotNull(header);
		assertEquals("ES256", header.getAlg());
		assertEquals("10", header.getIid());
		assertEquals("10:20230213", header.getKid());
		assertEquals(6, header.getMiv());
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
	public void testRejectsMissingIssuerSignedTicketBundle() throws Exception {
		assertThrows(IOException.class, () -> parser.parse(CBOR.writeValueAsBytes(new LinkedHashMap<>())));
	}

	@Test
	public void testRejectsBundleWithoutSignedElements() throws Exception {
		assertThrows(IOException.class, () -> parser.parse(encode(new byte[] { 1 })));
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

	private static byte[] encode(byte[]... elements) throws Exception {
		Map<String, Object> outer = new LinkedHashMap<>();
		outer.put("p", CBOR.writeValueAsBytes(elements));
		return CBOR.writeValueAsBytes(outer);
	}

}
