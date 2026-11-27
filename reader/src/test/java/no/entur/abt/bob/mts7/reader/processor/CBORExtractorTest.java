package no.entur.abt.bob.mts7.reader.processor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

public class CBORExtractorTest {

	private final CBORMapper cbor = new CBORMapper();
	private final CBORExtractor extractor = new CBORExtractor(cbor);

	@Test
	public void test() throws IOException {
		byte[] getNextData = ByteArrayHexStringConverter.hexStringToByteArray(
				"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C4603");

		String algorithm = extractor.parseAlgorithm(getNextData);
		assertEquals("ES256", algorithm);
	}

	@Test
	public void testAlgorithmIsFromTheTypeOfTheTokenPublicKey() throws IOException {
		// alg is the algorithm of the issuer signature, not of the card
		assertEquals("ES256", extractor.parseAlgorithm(bundle(h -> h.put("alg", "RS256"))));
		assertEquals("RS256", extractor.parseAlgorithm(bundle(h -> tpk(h).put("kty", "RSA"))));
		assertEquals("ES256", extractor.parseAlgorithm(bundle(h -> h.remove("alg"))));
	}

	@Test
	public void testUnknownOrMissingKeyType() throws IOException {
		assertNull(extractor.parseAlgorithm(bundle(h -> tpk(h).put("kty", "oct"))));
		assertNull(extractor.parseAlgorithm(bundle(h -> tpk(h).remove("kty"))));
		assertNull(extractor.parseAlgorithm(bundle(h -> h.put("tpk", "EC"))));
	}

	@Test
	public void testTruncatedHeader() throws IOException {
		byte[] header = cbor.writeValueAsBytes(header());
		// before kty in the token public key
		byte[] truncated = Arrays.copyOf(header, indexOf(header, "kty".getBytes(StandardCharsets.US_ASCII)) - 1);

		assertThrows(IOException.class, () -> extractor.extractAlgorithm(truncated));
	}

	private static int indexOf(byte[] data, byte[] value) {
		for (int i = 0; i + value.length <= data.length; i++) {
			if (Arrays.equals(Arrays.copyOfRange(data, i, i + value.length), value)) {
				return i;
			}
		}
		throw new IllegalArgumentException();
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> tpk(Map<String, Object> header) {
		return (Map<String, Object>) header.get("tpk");
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
		header.put("tpk", tpk);
		return header;
	}

	private byte[] bundle(Consumer<Map<String, Object>> change) throws IOException {
		Map<String, Object> header = header();
		change.accept(header);

		byte[][] elements = { cbor.writeValueAsBytes(header), cbor.writeValueAsBytes(new LinkedHashMap<>()), new byte[64] };

		Map<String, Object> outer = new LinkedHashMap<>();
		outer.put("v", new byte[] { 0x61, 0x31 });
		outer.put("p", cbor.writeValueAsBytes(elements));
		return cbor.writeValueAsBytes(outer);
	}
}
